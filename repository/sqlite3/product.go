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

// PRODUCT --------------------------------------------------------------------
// Params: :unique_id, :product_name, :product_type, :category, :product_description, :country_of_origin, :attrs
const tmplUpsertProduct = `
WITH
  row_try AS (
    INSERT INTO product(unique_id, product_name, product_type, category, product_description, country_of_origin)
    VALUES (:unique_id, :product_name, :product_type, :category, :product_description, :country_of_origin)
    ON CONFLICT(unique_id) DO UPDATE SET
      product_name        = COALESCE(excluded.product_name,        product.product_name),
      product_type        = COALESCE(excluded.product_type,        product.product_type),
      category            = COALESCE(excluded.category,            product.category),
      product_description = COALESCE(excluded.product_description, product.product_description),
      country_of_origin   = COALESCE(excluded.country_of_origin,   product.country_of_origin),
      updated_at          = CASE WHEN
        (excluded.product_name        IS NOT product.product_name) OR
        (excluded.product_type        IS NOT product.product_type) OR
        (excluded.category            IS NOT product.category) OR
        (excluded.product_description IS NOT product.product_description) OR
        (excluded.country_of_origin   IS NOT product.country_of_origin)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE product.updated_at END
    WHERE (excluded.product_name        IS NOT product.product_name) OR
          (excluded.product_type        IS NOT product.product_type) OR
          (excluded.category            IS NOT product.category) OR
          (excluded.product_description IS NOT product.product_description) OR
          (excluded.country_of_origin   IS NOT product.country_of_origin)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM product WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('product') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='product' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), COALESCE(:product_name,:unique_id), coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=COALESCE(:product_name,:unique_id) LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'product',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

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

func (s *Statements) UpsertProduct(ctx context.Context, a *oamplat.Product) (int64, error) {
	row := s.UpsertProductStmt.QueryRowContext(ctx,
		sql.Named("unique_id", a.ID),
		sql.Named("product_name", a.Name),
		sql.Named("product_type", a.Type),
		sql.Named("category", a.Category),
		sql.Named("product_description", a.Description),
		sql.Named("country_of_origin", a.CountryOfOrigin),
		sql.Named("attrs", "{}"),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchProductByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, unique_id, product_name, product_type, category, product_description, country_of_origin
		        FROM product WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "product", query)
	if err != nil {
		return nil, err
	}

	var a product
	var c, u *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.UniqueID, &a.ProductName, &a.ProductType, &a.Category, &a.ProductDescription, &a.CountryOfOrigin,
	); err != nil {
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
		CreatedAt: (*a.CreatedAt).In(time.UTC).Local(),
		LastSeen:  (*a.UpdatedAt).In(time.UTC).Local(),
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
