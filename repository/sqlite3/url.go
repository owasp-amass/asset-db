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
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// Params: :raw_url, :host, :url_path, :port, :scheme
const upsertURLText = `
INSERT INTO url(raw_url, host, url_path, port, scheme)
VALUES (lower(:raw_url), :host, :url_path, :port, :scheme)
ON CONFLICT(raw_url) DO UPDATE SET
  host       = COALESCE(excluded.host,       url.host),
  url_path   = COALESCE(excluded.url_path,   url.url_path),
  port       = COALESCE(excluded.port,       url.port),
  scheme     = COALESCE(excluded.scheme,     url.scheme),
  updated_at = CURRENT_TIMESTAMP`

// Param: :raw_url
const selectEntityIDByURLText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'url' LIMIT 1)
  AND natural_key = lower(:raw_url)
LIMIT 1`

// Param: :row_id
const selectURLByIDText = `
SELECT id, created_at, updated_at, raw_url, host, url_path, port, scheme 
FROM url
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertURL(ctx context.Context, a *oamurl.URL) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.url.upsert",
		SQLText: upsertURLText,
		Args: []any{
			sql.Named("raw_url", a.Raw),
			sql.Named("host", a.Host),
			sql.Named("url_path", a.Path),
			sql.Named("port", a.Port),
			sql.Named("scheme", a.Scheme),
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
		Name:    "asset.url.entity_id_by_url",
		SQLText: selectEntityIDByURLText,
		Args:    []any{sql.Named("raw_url", a.Raw)},
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

func (r *SqliteRepository) fetchURLByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.url.by_id",
		SQLText: selectURLByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var c, u string
	var row_id int64
	var a oamurl.URL
	if err := result.Row.Scan(&row_id, &c, &u, &a.Raw, &a.Host, &a.Path, &a.Port, &a.Scheme); err != nil {
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
