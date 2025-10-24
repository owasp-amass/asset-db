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

// URL ------------------------------------------------------------------------
// Params: :raw_url, :host, :url_path, :port, :scheme, :attrs
const tmplUpsertURL = `
WITH
  row_try AS (
    INSERT INTO url(raw_url, host, url_path, port, scheme)
    VALUES (:raw_url, :host, :url_path, :port, :scheme)
    ON CONFLICT(raw_url) DO UPDATE SET
      host       = COALESCE(excluded.host,       url.host),
      url_path   = COALESCE(excluded.url_path,   url.url_path),
      port       = COALESCE(excluded.port,       url.port),
      scheme     = COALESCE(excluded.scheme,     url.scheme),
      updated_at = CASE WHEN
        (excluded.host     IS NOT url.host) OR
        (excluded.url_path IS NOT url.url_path) OR
        (excluded.port     IS NOT url.port) OR
        (excluded.scheme   IS NOT url.scheme)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE url.updated_at END
    WHERE (excluded.host     IS NOT url.host) OR
          (excluded.url_path IS NOT url.url_path) OR
          (excluded.port     IS NOT url.port) OR
          (excluded.scheme   IS NOT url.scheme)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM url WHERE raw_url = :raw_url LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('url')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (
    SELECT id FROM ensure_type
    UNION ALL SELECT id FROM entity_type_lu WHERE name='url' LIMIT 1
  ),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :raw_url, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}'))
        ELSE entities.attrs
      END,
      updated_at = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (
    SELECT entity_id FROM ent_ins
    UNION ALL
    SELECT entity_id FROM entities
    WHERE type_id = (SELECT id FROM type_id) AND display_value = :raw_url
    LIMIT 1
  ),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id), 'url', (SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name, row_id) DO UPDATE SET
      entity_id  = excluded.entity_id,
      updated_at = strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

type URLAsset struct {
	ID        int64      `json:"id"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	RawURL    string     `json:"raw_url"`
	Host      string     `json:"host"`
	URLPath   *string    `json:"url_path,omitempty"`
	Port      *int64     `json:"port,omitempty"`
	Scheme    *string    `json:"scheme,omitempty"`
}

func (s *Statements) UpsertURL(ctx context.Context, url *URLAsset, attrsJSON string) (int64, error) {
	row := s.UpsertURLStmt.QueryRowContext(ctx,
		sql.Named("raw_url", url.RawURL),
		sql.Named("host", url.Host),
		sql.Named("url_path", url.URLPath),
		sql.Named("port", url.Port),
		sql.Named("scheme", url.Scheme),
		sql.Named("attrs", attrsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchURLByRowID(ctx context.Context, rowID int64) (*URLAsset, error) {
	query := `SELECT id, created_at, updated_at, raw_url, host, url_path, port, scheme
		      FROM url WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "url", query)
	if err != nil {
		return nil, err
	}

	var a URLAsset
	var port *int64
	var c, u *string
	if err := st.QueryRowContext(ctx, rowID).Scan(&a.ID, &c, &u, &a.RawURL, &a.Host, &a.URLPath, &port, &a.Scheme); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	a.Port = port
	return &a, nil
}
