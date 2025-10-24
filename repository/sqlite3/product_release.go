// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// PRODUCTRELEASE -------------------------------------------------------------
// Params: :release_name, :release_date, :attrs
const tmplUpsertProductRelease = `
WITH
  row_try AS (
    INSERT INTO productrelease(release_name, release_date)
    VALUES (:release_name, :release_date)
    ON CONFLICT(release_name) DO UPDATE SET
      release_date = COALESCE(excluded.release_date, productrelease.release_date),
      updated_at   = CASE WHEN (excluded.release_date IS NOT productrelease.release_date)
                     THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE productrelease.updated_at END
    WHERE (excluded.release_date IS NOT productrelease.release_date)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM productrelease WHERE release_name=:release_name LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('productrelease') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='productrelease' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :release_name, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:release_name LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'productrelease',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

type ProductRelease struct {
	ID          int64      `json:"id"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	ReleaseName string     `json:"release_name"`
	ReleaseDate *time.Time `json:"release_date,omitempty"`
}

func (s *Statements) UpsertProductRelease(ctx context.Context, release *ProductRelease, attrsJSON string) (int64, error) {
	row := s.UpsertProductReleaseStmt.QueryRowContext(ctx,
		sql.Named("release_name", release.ReleaseName),
		sql.Named("release_date", release.ReleaseDate),
		sql.Named("attrs", attrsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchProductReleaseByRowID(ctx context.Context, rowID int64) (*ProductRelease, error) {
	query := `SELECT id, created_at, updated_at, release_name, release_date
		      FROM productrelease WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "productrelease", query)
	if err != nil {
		return nil, err
	}

	var a ProductRelease
	var c, u, rd *string
	if err := st.QueryRowContext(ctx, rowID).Scan(&a.ID, &c, &u, &a.ReleaseName, &rd); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	a.ReleaseDate = parseTS(rd)
	return &a, nil
}
