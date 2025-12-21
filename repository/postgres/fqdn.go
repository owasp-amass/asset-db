// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// Params: @record::jsonb
const upsertFQDNText = `SELECT public.fqdn_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectFQDNByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.fqdn, a.attrs
FROM public.fqdn_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectFQDNFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.fqdn, a.attrs 
FROM public.fqdn_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectFQDNSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.fqdn, a.attrs 
FROM public.fqdn_updated_since(@since::timestamp, @limit::integer) AS a;`

func (r *PostgresRepository) upsertFQDN(ctx context.Context, a *oamdns.FQDN) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid FQDN provided")
	}
	if a.Name == "" {
		return 0, errors.New("FQDN name cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.fqdn.upsert",
		SQLText: upsertFQDNText,
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

func (r *PostgresRepository) fetchFQDNByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.fqdn.by_id",
		SQLText: selectFQDNByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var rid int64
	var a oamdns.FQDN
	var c, u time.Time
	var attrsJSON string
	if err := result.Row.Scan(&rid, &c, &u, &a.Name, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildFQDNEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findFQDNsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
		Name:    "asset.fqdn.find_by_content",
		SQLText: selectFQDNFindByContentText,
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
		var a oamdns.FQDN
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.Name, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildFQDNEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getFQDNsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
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
		Name:    "asset.fqdn.updated_since",
		SQLText: selectFQDNSinceText,
		Args: pgx.NamedArgs{
			"since": since,
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
		var a oamdns.FQDN
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.Name, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildFQDNEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildFQDNEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamdns.FQDN) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no FQDN record found")
	}
	if a.Name == "" {
		return nil, errors.New("FQDN name is missing")
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
