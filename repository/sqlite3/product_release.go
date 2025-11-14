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

// Params: :release_name, :attrs
const upsertProductReleaseText = `
INSERT INTO productrelease(release_name, attrs)
VALUES (:release_name, :attrs)
ON CONFLICT(release_name_norm) DO UPDATE SET
    attrs      = COALESCE(excluded.attrs, productrelease.attrs),
    updated_at = CURRENT_TIMESTAMP`

// Param: :release_name
const selectEntityIDByProductReleaseText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'productrelease' LIMIT 1)
  AND natural_key = lower(:release_name)
LIMIT 1`

// Param: :row_id
const selectProductReleaseByIDText = `
SELECT id, created_at, updated_at, release_name, attrs 
FROM productrelease
WHERE id = :row_id
LIMIT 1`

type productReleaseAttributes struct {
	ReleaseDate string `json:"release_date"`
}

func (r *SqliteRepository) upsertProductRelease(ctx context.Context, a *oamplat.ProductRelease) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid product release provided")
	}
	if a.Name == "" {
		return 0, fmt.Errorf("the product release name cannot be empty")
	}

	attrs := productReleaseAttributes{
		ReleaseDate: a.ReleaseDate,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.product_release.upsert",
		SQLText: upsertProductReleaseText,
		Args: []any{
			sql.Named("release_name", a.Name),
			sql.Named("attrs", string(attrsJSON)),
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
		Name:    "asset.product_release.entity_id_by_product_release",
		SQLText: selectEntityIDByProductReleaseText,
		Args:    []any{sql.Named("release_name", a.Name)},
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

func (r *SqliteRepository) fetchProductReleaseByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.product_release.by_id",
		SQLText: selectProductReleaseByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var c, u, attrsJSON string
	var a oamplat.ProductRelease
	if err := result.Row.Scan(&row_id, &c, &u, &a.Name, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, fmt.Errorf("no product release found with row ID %d", rowID)
	}
	if a.Name == "" {
		return nil, fmt.Errorf("product release at row ID %d has no name", rowID)
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

	var attrs productReleaseAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.ReleaseDate = attrs.ReleaseDate

	return e, nil
}
