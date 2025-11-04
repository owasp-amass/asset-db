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
	oamfile "github.com/owasp-amass/open-asset-model/file"
)

// Params: :file_url, :basename, :file_type
const upsertFileText = `
INSERT INTO file(file_url, basename, file_type)
VALUES (lower(:file_url), :basename, :file_type)
ON CONFLICT(file_url) DO UPDATE SET
    basename   = COALESCE(excluded.basename,  file.basename),
    file_type  = COALESCE(excluded.file_type, file.file_type),
    updated_at = CURRENT_TIMESTAMP`

// Param: :file_url
const selectEntityIDByFileText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'file' LIMIT 1)
  AND natural_key = lower(:file_url)
LIMIT 1`

// Param: :row_id
const selectFileByID = `
SELECT id, created_at, updated_at, file_url, basename, file_type 
FROM file
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertFile(ctx context.Context, a *oamfile.File) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.file.upsert",
		SQLText: upsertFileText,
		Args: []any{
			sql.Named("file_url", a.URL),
			sql.Named("basename", a.Name),
			sql.Named("file_type", a.Type),
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
		Name:    "asset.file.entity_id_by_file",
		SQLText: selectEntityIDByFileText,
		Args:    []any{sql.Named("file_url", a.URL)},
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

func (r *SqliteRepository) fetchFileByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.file.by_id",
		SQLText: selectFileByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var c, u string
	var row_id int64
	var a oamfile.File
	if err := result.Row.Scan(&row_id, &c, &u, &a.URL, &a.Name, &a.Type); err != nil {
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
