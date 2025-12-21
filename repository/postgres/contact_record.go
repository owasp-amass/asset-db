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
	"github.com/owasp-amass/asset-db/types"
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

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.contact.upsert",
		SQLText: upsertContactRecordText,
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

func (r *PostgresRepository) fetchContactRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.contact.by_id",
		SQLText: selectContactRecordByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var rid int64
	var c, u time.Time
	var attrsJSON string
	var a contact.ContactRecord
	if err := result.Row.Scan(&rid, &c, &u, &a.DiscoveredAt, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildContactRecordEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findContactRecordsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
		Name:    "asset.contact.find_by_content",
		SQLText: selectContactRecordFindByContentText,
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
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string
		var a contact.ContactRecord

		if err := result.Rows.Scan(&eid, &rid, &c,
			&u, &a.DiscoveredAt, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildContactRecordEntity(
			eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getContactRecordsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*types.Entity, error) {
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
		Name:    "asset.contact.updated_since",
		SQLText: selectContactRecordSinceText,
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
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string
		var a contact.ContactRecord

		if err := result.Rows.Scan(&eid, &rid, &c,
			&u, &a.DiscoveredAt, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildContactRecordEntity(
			eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildContactRecordEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *contact.ContactRecord) (*types.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no contact record found")
	}
	if a.DiscoveredAt == "" {
		return nil, errors.New("contact record discovered_at is missing")
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
