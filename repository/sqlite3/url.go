// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// Params: :raw_url, :scheme:, :attrs
const upsertURLText = `
INSERT INTO url(raw_url, scheme, attrs)
VALUES (lower(:raw_url), :scheme, :attrs)
ON CONFLICT(raw_url) DO UPDATE SET
  scheme     = COALESCE(excluded.scheme, url.scheme),
  attrs      = COALESCE(excluded.attrs,  url.attrs),
  updated_at = CURRENT_TIMESTAMP`

// Param: :raw_url
const selectEntityIDByURLText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'url' LIMIT 1)
  AND natural_key = lower(:raw_url)
LIMIT 1`

// Param: :row_id
const selectURLByIDText = `
SELECT id, created_at, updated_at, raw_url, scheme, attrs
FROM url
WHERE id = :row_id
LIMIT 1`

type urlAttributes struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Path     string `json:"path"`
	Options  string `json:"options"`
	Fragment string `json:"fragment"`
}

func (r *SqliteRepository) upsertURL(ctx context.Context, a *oamurl.URL) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid URL provided")
	}
	if a.Raw == "" {
		return 0, fmt.Errorf("the URL raw string cannot be empty")
	}

	attrs := urlAttributes{
		Username: a.Username,
		Password: a.Password,
		Host:     a.Host,
		Port:     a.Port,
		Path:     a.Path,
		Options:  a.Options,
		Fragment: a.Fragment,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.url.upsert",
		SQLText: upsertURLText,
		Args: []any{
			sql.Named("raw_url", a.Raw),
			sql.Named("scheme", a.Scheme),
			sql.Named("attrs", string(attrsJSON)),
		},
		Result: done,
	})
	err = <-done
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

	var row_id int64
	var a oamurl.URL
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.Raw, &a.Scheme, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, fmt.Errorf("no URL found with row ID %d", rowID)
	}
	if a.Raw == "" {
		return nil, fmt.Errorf("URL at row ID %d has a missing raw string", rowID)
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

	var attrs urlAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Username = attrs.Username
	a.Password = attrs.Password
	a.Host = attrs.Host
	a.Port = attrs.Port
	a.Path = attrs.Path
	a.Options = attrs.Options
	a.Fragment = attrs.Fragment

	return e, nil
}
