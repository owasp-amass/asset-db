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

// Params: :file_url, :basename, :file_type
const upsertFileText = `
INSERT INTO file(file_url, basename, file_type)
VALUES (lower(:file_url), :basename, :file_type)
ON CONFLICT(file_url) DO UPDATE SET
    basename   = COALESCE(excluded.basename,  file.basename),
    file_type  = COALESCE(excluded.file_type, file.file_type),
    updated_at = CURRENT_TIMESTAMP;`

// Param: :file_url
const selectEntityIDByFileText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'file' LIMIT 1)
  AND display_value = lower(:file_url)
LIMIT 1;`

// Param: :row_id
const selectFileByID = `
SELECT id, created_at, updated_at, file_url, basename, file_type 
FROM file
WHERE id = :row_id
LIMIT 1;`

func (r *SqliteRepository) upsertFile(ctx context.Context, a *oamfile.File) (int64, error) {
	const keySel = "asset.file.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertFileText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("file_url", a.URL),
		sql.Named("basename", a.Name),
		sql.Named("file_type", a.Type),
	)

	const keySel2 = "asset.file.entity_id_by_file"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByFileText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("file_url", a.URL)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchFileByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.file.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectFileByID)
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
		CreatedAt: created.In(time.UTC).Local(),
		LastSeen:  updated.In(time.UTC).Local(),
		Asset: &oamfile.File{
			URL:  url,
			Name: fname,
			Type: ftype,
		},
	}, nil
}
