// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: @record::jsonb
const upsertProductText = `SELECT public.product_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectProductByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.product_name, a.product_type, a.attrs
FROM public.product_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectProductFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.product_name, a.product_type, a.attrs 
FROM public.product_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectProductSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.product_name, a.product_type, a.attrs 
FROM public.product_updated_since(@since::timestamp, @limit::integer) AS a;`

type productAttributes struct {
	Category        string `json:"category,omitempty"`
	Description     string `json:"description,omitempty"`
	CountryOfOrigin string `json:"country_of_origin,omitempty"`
}

func (r *PostgresRepository) upsertProduct(ctx context.Context, a *oamplat.Product) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid product provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("the product does not have a unique identifier")
	}
	if a.Name == "" {
		return 0, fmt.Errorf("the product name cannot be empty")
	}
	if a.Type == "" {
		return 0, fmt.Errorf("the product type cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.product.upsert",
		SQLText: upsertProductText,
		Args:    pgx.NamedArgs{"record": string(record)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return 0, result.Err
	}

	var id int64
	if err := result.Row.Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *PostgresRepository) fetchProductByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.product.by_id",
		SQLText: selectProductByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var rid int64
	var c, u time.Time
	var attrsJSON string
	var a oamplat.Product
	if err := result.Row.Scan(&rid, &c, &u, &a.ID, &a.Name, &a.Type, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildProductEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findProductsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
	if !since.IsZero() {
		since = since.UTC()
	}
	ts := zeronull.Timestamp(since)

	if len(filters) == 0 {
		return nil, errors.New("no filters provided")
	}

	filtersJSON, err := json.Marshal(filters)
	if err != nil {
		return nil, err
	}

	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.product.find_by_content",
		SQLText: selectProductFindByContentText,
		Args: pgx.NamedArgs{
			"filters": string(filtersJSON),
			"since":   ts,
			"limit":   limit,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string
		var a oamplat.Product

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.ID, &a.Name, &a.Type, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildProductEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getProductsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.product.updated_since",
		SQLText: selectProductSinceText,
		Args: pgx.NamedArgs{
			"since": since.UTC(),
			"limit": lmt,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string
		var a oamplat.Product

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.ID, &a.Name, &a.Type, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildProductEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildProductEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamplat.Product) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, fmt.Errorf("product at row ID %d not found", rid)
	}
	if a.ID == "" {
		return nil, fmt.Errorf("product unique ID is missing")
	}
	if a.Name == "" {
		return nil, fmt.Errorf("product name is missing")
	}
	if a.Type == "" {
		return nil, fmt.Errorf("product type is missing")
	}

	var attrs productAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Category = attrs.Category
	a.Description = attrs.Description
	a.CountryOfOrigin = attrs.CountryOfOrigin

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
