// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// Params: @record::jsonb
const upsertURLText = `SELECT public.url_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectURLByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.raw_url, a.scheme, a.attrs
FROM public.url_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectURLFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.raw_url, a.scheme, a.attrs 
FROM public.url_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectURLSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.raw_url, a.scheme, a.attrs 
FROM public.url_updated_since(@since::timestamp, @limit::integer) AS a;`

type urlAttributes struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path,omitempty"`
	Options  string `json:"options,omitempty"`
	Fragment string `json:"fragment,omitempty"`
}

func (r *PostgresRepository) upsertURL(ctx context.Context, a *oamurl.URL) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid URL provided")
	}
	if a.Raw == "" {
		return 0, fmt.Errorf("the URL raw string cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.url.upsert",
		SQLText: upsertURLText,
		Args:    pgx.NamedArgs{"record": string(record)},
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

func (r *PostgresRepository) fetchURLByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.url.by_id",
		SQLText: selectURLByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var rid int64
	var a oamurl.URL
	var c, u time.Time
	var attrsJSON string
	if err := result.Row.Scan(&rid, &c, &u, &a.Raw, &a.Scheme, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildURLEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findURLsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
	if !since.IsZero() {
		since = since.UTC()
	}
	ts := zeronull.Timestamp(since)

	if len(filters) == 0 {
		return nil, errors.New("no filters provided")
	}

	filtersJSON, err := json.Marshal(filters)
	if err != nil {
		return nil, err
	}

	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.url.find_by_content",
		SQLText: selectURLFindByContentText,
		Args: pgx.NamedArgs{
			"filters": string(filtersJSON),
			"since":   ts,
			"limit":   limit,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var a oamurl.URL
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.Raw, &a.Scheme, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildURLEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getURLsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.url.updated_since",
		SQLText: selectURLSinceText,
		Args: pgx.NamedArgs{
			"since": since.UTC(),
			"limit": lmt,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var a oamurl.URL
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.Raw, &a.Scheme, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildURLEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildURLEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamurl.URL) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, fmt.Errorf("no URL found with row ID %d", rid)
	}
	if a.Raw == "" {
		return nil, fmt.Errorf("URL at row ID %d has a missing raw string", rid)
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

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
