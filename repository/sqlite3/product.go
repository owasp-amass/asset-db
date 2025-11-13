// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: :unique_id, :product_name, :product_type, :attrs
const upsertProductText = `
INSERT INTO product(unique_id, product_name, product_type, attrs)
VALUES (:unique_id, :product_name, :product_type, :attrs)
ON CONFLICT(unique_id) DO UPDATE SET
    product_name        = COALESCE(excluded.product_name,        product.product_name),
    product_type        = COALESCE(excluded.product_type,        product.product_type),
    attrs               = COALESCE(excluded.attrs,               product.attrs),
    updated_at          = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByProductText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'product' LIMIT 1)
  AND natural_key = :unique_id
LIMIT 1`

// Param: :row_id
const selectProductByIDText = `
SELECT id, created_at, updated_at, unique_id, product_name, product_type, attrs
FROM product 
WHERE id = :row_id
LIMIT 1`

type productAttributes struct {
	Category        string `json:"category"`
	Description     string `json:"description"`
	CountryOfOrigin string `json:"country_of_origin"`
}

func (r *SqliteRepository) upsertProduct(ctx context.Context, a *oamplat.Product) (int64, error) {
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

	attrs := productAttributes{
		Category:        a.Category,
		Description:     a.Description,
		CountryOfOrigin: a.CountryOfOrigin,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.product.upsert",
		SQLText: upsertProductText,
		Args: []any{
			sql.Named("unique_id", a.ID),
			sql.Named("product_name", a.Name),
			sql.Named("product_type", a.Type),
			sql.Named("attrs", attrsJSON),
		},
		Result: done,
	})
	err = <-done
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.product.entity_id_by_product",
		SQLText: selectEntityIDByProductText,
		Args:    []any{sql.Named("unique_id", a.ID)},
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

func (r *SqliteRepository) fetchProductByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.product.by_id",
		SQLText: selectProductByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
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
