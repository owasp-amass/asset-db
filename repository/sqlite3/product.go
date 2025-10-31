// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: :unique_id, :product_name, :product_type, :category, :product_description, :country_of_origin
const upsertProductText = `
INSERT INTO product(unique_id, product_name, product_type, category, product_description, country_of_origin)
VALUES (:unique_id, :product_name, :product_type, :category, :product_description, :country_of_origin)
ON CONFLICT(unique_id) DO UPDATE SET
    product_name        = COALESCE(excluded.product_name,        product.product_name),
    product_type        = COALESCE(excluded.product_type,        product.product_type),
    category            = COALESCE(excluded.category,            product.category),
    product_description = COALESCE(excluded.product_description, product.product_description),
    country_of_origin   = COALESCE(excluded.country_of_origin,   product.country_of_origin),
    updated_at          = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByProductText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'product' LIMIT 1)
  AND display_value = :unique_id
LIMIT 1`

// Param: :row_id
const selectProductByIDText = `
SELECT id, created_at, updated_at, unique_id, product_name, product_type, category, product_description, country_of_origin 
FROM product 
WHERE id = :row_id
LIMIT 1`

type product struct {
	ID                 int64      `json:"id"`
	CreatedAt          *time.Time `json:"created_at,omitempty"`
	UpdatedAt          *time.Time `json:"updated_at,omitempty"`
	UniqueID           string     `json:"unique_id"`
	ProductName        string     `json:"product_name"`
	ProductType        *string    `json:"product_type,omitempty"`
	Category           *string    `json:"category,omitempty"`
	ProductDescription *string    `json:"product_description,omitempty"`
	CountryOfOrigin    *string    `json:"country_of_origin,omitempty"`
}

func (r *SqliteRepository) upsertProduct(ctx context.Context, a *oamplat.Product) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.product.upsert",
		SQLText: upsertProductText,
		Args: []any{
			sql.Named("unique_id", a.ID),
			sql.Named("product_name", a.Name),
			sql.Named("product_type", a.Type),
			sql.Named("category", a.Category),
			sql.Named("product_description", a.Description),
			sql.Named("country_of_origin", a.CountryOfOrigin),
		},
		Result: done,
	})
	err := <-done
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

	var a product
	var c, u *string
	if err := result.Row.Scan(&a.ID, &c, &u, &a.UniqueID, &a.ProductName,
		&a.ProductType, &a.Category, &a.ProductDescription, &a.CountryOfOrigin); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	if a.CreatedAt == nil || a.UpdatedAt == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var ptype, category, description, country string
	if a.ProductType != nil {
		ptype = *a.ProductType
	}
	if a.Category != nil {
		category = *a.Category
	}
	if a.ProductDescription != nil {
		description = *a.ProductDescription
	}
	if a.CountryOfOrigin != nil {
		country = *a.CountryOfOrigin
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: a.CreatedAt.In(time.UTC).Local(),
		LastSeen:  a.UpdatedAt.In(time.UTC).Local(),
		Asset: &oamplat.Product{
			ID:              a.UniqueID,
			Name:            a.ProductName,
			Type:            ptype,
			Category:        category,
			Description:     description,
			CountryOfOrigin: country,
		},
	}, nil
}
