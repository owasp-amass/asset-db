// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Params: @record::jsonb
const upsertAutonomousSystemText = `SELECT public.autonomoussystem_upsert_entity_json(@record::jsonb);`

// Param: @row_id
const selectAutonomousSystemByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.asn, a.attrs
FROM public.autonomoussystem_get_by_id(@row_id) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectAutonomousSystemFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.asn, a.attrs 
FROM public.autonomoussystem_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectAutonomousSystemSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.asn, a.attrs 
FROM public.autonomoussystem_updated_since(@since::timestamp, @limit::integer) AS a;`

func (r *PostgresRepository) upsertAutonomousSystem(ctx context.Context, a *oamnet.AutonomousSystem) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid autonomous system provided")
	}
	if a.Number == 0 {
		return 0, errors.New("autonomous system number cannot be zero")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertAutonomousSystemText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.wpool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchAutonomousSystemByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var rid int64
	var c, u time.Time
	var attrsJSON string
	var a oamnet.AutonomousSystem

	j := NewRowJob(ctx, selectAutonomousSystemByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(&rid, &c, &u, &a.Number, &attrsJSON)
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	e, err := r.buildAutonomousSystemEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findAutonomousSystemsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	j := NewRowsJob(ctx, selectAutonomousSystemFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamnet.AutonomousSystem

			if err := rows.Scan(&eid, &rid, &c,
				&u, &a.Number, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildAutonomousSystemEntity(
				eid, rid, c, u, attrsJSON, &a); err == nil {
				out = append(out, ent)
			}
		}
		return rows.Err()
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

func (r *PostgresRepository) getAutonomousSystemsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectAutonomousSystemSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamnet.AutonomousSystem

			if err := rows.Scan(&eid, &rid, &c,
				&u, &a.Number, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildAutonomousSystemEntity(
				eid, rid, c, u, attrsJSON, &a); err == nil {
				out = append(out, ent)
			}
		}
		return rows.Err()
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

func (r *PostgresRepository) buildAutonomousSystemEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamnet.AutonomousSystem) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no autonomous system record found")
	}
	if a.Number < 0 {
		return nil, errors.New("autonomous system number is missing")
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
