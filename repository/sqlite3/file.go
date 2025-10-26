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
	oamfile "github.com/owasp-amass/open-asset-model/file"
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

func (s *Statements) UpsertFile(ctx context.Context, a *oamfile.File) (int64, error) {
	row := s.UpsertFileStmt.QueryRowContext(ctx,
		sql.Named("file_url", a.URL),
		sql.Named("basename", a.Name),
		sql.Named("file_type", a.Type),
		sql.Named("attrs", ""),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchFileByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, file_url, basename, file_type FROM file WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "file", query)
	if err != nil {
		return nil, err
	}

	var id int64
	var url string
	var c, u, fn, ft *string
	if err := st.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &url, &fn, &ft); err != nil {
		return nil, err
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var fname string
	if fn != nil {
		fname = *fn
	}

	var ftype string
	if ft != nil {
		ftype = *ft
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: (*created).In(time.UTC).Local(),
		LastSeen:  (*updated).In(time.UTC).Local(),
		Asset: &oamfile.File{
			URL:  url,
			Name: fname,
			Type: ftype,
		},
	}, nil
}
