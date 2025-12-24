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

	var id int64
	j := NewRowJob(ctx, upsertFQDNText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.pool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchFQDNByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var rid int64
	var a oamdns.FQDN
	var c, u time.Time
	var attrsJSON string

	j := NewRowJob(ctx, selectFQDNByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(&rid, &c, &u, &a.Name, &attrsJSON)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	e, err := r.buildFQDNEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findFQDNsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectFQDNFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var a oamdns.FQDN
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string

			if err := rows.Scan(&eid, &rid, &c, &u, &a.Name, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildFQDNEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
				out = append(out, ent)
			}
		}
		return rows.Err()
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
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

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectFQDNSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var a oamdns.FQDN
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string

			if err := rows.Scan(&eid, &rid, &c, &u, &a.Name, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildFQDNEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
				out = append(out, ent)
			}
		}
		return rows.Err()
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
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
