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
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: @record::jsonb
const upsertContactRecordText = `SELECT public.contactrecord_upsert_entity_json(@record::jsonb);`

// Param: @row_id
const selectContactRecordByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.discovered_at, a.attrs
FROM public.contactrecord_get_by_id(@row_id) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectContactRecordFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.discovered_at, a.attrs 
FROM public.contactrecord_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectContactRecordSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.discovered_at, a.attrs 
FROM public.contactrecord_updated_since(@since::timestamp, @limit::integer) AS a;`

func (r *PostgresRepository) upsertContactRecord(ctx context.Context, a *contact.ContactRecord) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid contact record provided")
	}
	if a.DiscoveredAt == "" {
		return 0, errors.New("contact record discovered_at cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertContactRecordText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.wpool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchContactRecordByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var rid int64
	var c, u time.Time
	var attrsJSON string
	var a contact.ContactRecord

	j := NewRowJob(ctx, selectContactRecordByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(&rid, &c, &u, &a.DiscoveredAt, &attrsJSON)
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	e, err := r.buildContactRecordEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findContactRecordsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	j := NewRowsJob(ctx, selectContactRecordFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a contact.ContactRecord

			if err := rows.Scan(&eid, &rid, &c,
				&u, &a.DiscoveredAt, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildContactRecordEntity(
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

func (r *PostgresRepository) getContactRecordsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectContactRecordSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a contact.ContactRecord

			if err := rows.Scan(&eid, &rid, &c,
				&u, &a.DiscoveredAt, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildContactRecordEntity(
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

func (r *PostgresRepository) buildContactRecordEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *contact.ContactRecord) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no contact record found")
	}
	if a.DiscoveredAt == "" {
		return nil, errors.New("contact record discovered_at is missing")
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
