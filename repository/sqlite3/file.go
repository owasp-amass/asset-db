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

// FILE -----------------------------------------------------------------------
// Params: :file_url, :basename, :file_type, :attrs
const tmplUpsertFile = `
WITH
  row_try AS (
    INSERT INTO file(file_url, basename, file_type)
    VALUES (:file_url, :basename, :file_type)
    ON CONFLICT(file_url) DO UPDATE SET
      basename   = COALESCE(excluded.basename,  file.basename),
      file_type  = COALESCE(excluded.file_type, file.file_type),
      updated_at = CASE WHEN
        (excluded.basename IS NOT file.basename) OR
        (excluded.file_type IS NOT file.file_type)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE file.updated_at END
    WHERE (excluded.basename IS NOT file.basename) OR
          (excluded.file_type IS NOT file.file_type)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM file WHERE file_url=:file_url LIMIT 1),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('file')
    ON CONFLICT(name) DO NOTHING RETURNING id
  ),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='file' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :file_url, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins
             UNION ALL SELECT entity_id FROM entities
             WHERE type_id=(SELECT id FROM type_id) AND display_value=:file_url LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'file',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

type FileAsset struct {
	ID        int64      `json:"id"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	FileURL   string     `json:"file_url"`
	Basename  *string    `json:"basename,omitempty"`
	FileType  *string    `json:"file_type,omitempty"`
}

func (s *Statements) UpsertFile(ctx context.Context, fileURL, basename, fileType, attrsJSON string) (int64, error) {
	row := s.UpsertFileStmt.QueryRowContext(ctx,
		sql.Named("file_url", fileURL),
		sql.Named("basename", basename),
		sql.Named("file_type", fileType),
		sql.Named("attrs", attrsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchFileByRowID(ctx context.Context, rowID int64) (*FileAsset, error) {
	query := `SELECT id, created_at, updated_at, file_url, basename, file_type FROM file WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "file", query)
	if err != nil {
		return nil, err
	}

	var a FileAsset
	var c, u *string
	if err := st.QueryRowContext(ctx, rowID).Scan(&a.ID, &c, &u, &a.FileURL, &a.Basename, &a.FileType); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	return &a, nil
}
