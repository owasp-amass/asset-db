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
  updated_at = CURRENT_TIMESTAMP;`

// Param: :raw_url
const selectEntityIDByURLText = `
SELECT entity_id FROM entities
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'url')
  AND display_value = lower(:raw_url)
LIMIT 1;`

// Param: :row_id
const selectURLByIDText = `
SELECT id, created_at, updated_at, raw_url, host, url_path, port, scheme 
FROM url
WHERE id = :row_id
LIMIT 1;`

func (r *SqliteRepository) upsertURL(ctx context.Context, a *oamurl.URL) (int64, error) {
	const keySel = "asset.url.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertURLText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("raw_url", a.Raw),
		sql.Named("host", a.Host),
		sql.Named("url_path", a.Path),
		sql.Named("port", a.Port),
		sql.Named("scheme", a.Scheme),
	)

	const keySel2 = "asset.url.entity_id_by_url"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByURLText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("raw_url", a.Raw)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchURLByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.url.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectURLByIDText)
	if err != nil {
		return nil, err
	}

	var id int64
	var raw, host string
	var p, sch *string
	var portptr *int64
	var c, u *string
	if err := st.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &raw, &host, &p, &portptr, &sch); err != nil {
		return nil, err
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var path, scheme string
	if p != nil {
		path = *p
	}
	if sch != nil {
		scheme = *sch
	}

	var port int
	if portptr != nil {
		port = int(*portptr)
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: created.In(time.UTC).Local(),
		LastSeen:  updated.In(time.UTC).Local(),
		Asset: &oamurl.URL{
			Raw:    raw,
			Scheme: scheme,
			Host:   host,
			Port:   port,
			Path:   path,
		},
	}, nil
}
