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
	"github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: @record::jsonb
const upsertProductText = `SELECT public.product_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectProductByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.product_name, a.product_type, a.attrs
FROM public.product_get_by_id(@row_id::bigint) AS a;`

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

func (r *PostgresRepository) fetchProductByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
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

	var row_id int64
	var a oamplat.Product
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.ID, &a.Name, &a.Type, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, fmt.Errorf("product at row ID %d not found", rowID)
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

	e := &types.Entity{ID: strconv.FormatInt(eid, 10), Asset: &a}
	if created, err := parseTimestamp(c); err != nil {
		return nil, err
	} else {
		e.CreatedAt = created.In(time.UTC).Local()
	}
	if updated, err := parseTimestamp(u); err != nil {
		return nil, err
	} else {
		e.LastSeen = updated.In(time.UTC).Local()
	}

	var attrs productAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Category = attrs.Category
	a.Description = attrs.Description
	a.CountryOfOrigin = attrs.CountryOfOrigin

	return e, nil
}
