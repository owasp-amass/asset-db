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

// Params: :release_name, :release_date
const upsertProductReleaseText = `
INSERT INTO productrelease(release_name, release_date)
VALUES (lower(:release_name), :release_date)
ON CONFLICT(release_name) DO UPDATE SET
    release_date = COALESCE(excluded.release_date, productrelease.release_date),
    updated_at   = CURRENT_TIMESTAMP;`

// Param: :release_name
const selectEntityIDByProductReleaseText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'productrelease' LIMIT 1)
  AND display_value = lower(:release_name)
LIMIT 1;`

// Param: :row_id
const selectProductReleaseByIDText = `
SELECT id, created_at, updated_at, release_name, release_date 
FROM productrelease
WHERE id = :row_id
LIMIT 1;`

func (r *SqliteRepository) upsertProductRelease(ctx context.Context, a *oamplat.ProductRelease) (int64, error) {
	const keySel = "asset.product_release.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertProductReleaseText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("release_name", a.Name),
		sql.Named("release_date", a.ReleaseDate),
	)

	const keySel2 = "asset.product_release.entity_id_by_product_release"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByProductReleaseText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("release_name", a.Name)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchProductReleaseByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.product_release.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectProductReleaseByIDText)
	if err != nil {
		return nil, err
	}

	var id int64
	var name string
	var c, u, rd *string
	if err := st.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &name, &rd); err != nil {
		return nil, err
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var rdate string
	if rd != nil {
		rdate = *rd
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: created.In(time.UTC).Local(),
		LastSeen:  updated.In(time.UTC).Local(),
		Asset: &oamplat.ProductRelease{
			Name:        name,
			ReleaseDate: rdate,
		},
	}, nil
}
