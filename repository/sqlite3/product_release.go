// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: :release_name, :release_date
const upsertProductReleaseText = `
INSERT INTO productrelease(release_name, release_date)
VALUES (lower(:release_name), :release_date)
ON CONFLICT(release_name) DO UPDATE SET
    release_date = COALESCE(excluded.release_date, productrelease.release_date),
    updated_at   = CURRENT_TIMESTAMP`

// Param: :release_name
const selectEntityIDByProductReleaseText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'productrelease' LIMIT 1)
  AND natural_key = lower(:release_name)
LIMIT 1`

// Param: :row_id
const selectProductReleaseByIDText = `
SELECT id, created_at, updated_at, release_name, release_date 
FROM productrelease
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertProductRelease(ctx context.Context, a *oamplat.ProductRelease) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.product_release.upsert",
		SQLText: upsertProductReleaseText,
		Args: []any{
			sql.Named("release_name", a.Name),
			sql.Named("release_date", a.ReleaseDate),
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

	var c, u string
	var row_id int64
	var a oamplat.ProductRelease
	if err := result.Row.Scan(&row_id, &c, &u, &a.Name, &a.ReleaseDate); err != nil {
		return nil, err
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

	return e, nil
}
