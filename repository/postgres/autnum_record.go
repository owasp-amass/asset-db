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
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Params: @record::jsonb
const upsertAutnumRecordText = `SELECT public.autnumrecord_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectAutnumByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.handle, a.asn, a.record_name, a.whois_server, a.attrs
FROM autnumrecord_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectAutnumFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.handle, a.asn, a.record_name, a.whois_server, a.attrs 
FROM public.autnumrecord_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectAutnumSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.handle, a.asn, a.record_name, a.whois_server, a.attrs 
FROM public.autnumrecord_updated_since(@since::timestamp, @limit::integer) AS a;`

type autnumAttributes struct {
	Raw         string   `json:"raw,omitempty"`
	Status      []string `json:"status,omitempty"`
	CreatedDate string   `json:"created_date,omitempty"`
	UpdatedDate string   `json:"updated_date,omitempty"`
}

func (r *PostgresRepository) upsertAutnumRecord(ctx context.Context, a *oamreg.AutnumRecord) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid autnum record provided")
	}
	if a.Name == "" {
		return 0, errors.New("autnum record name cannot be empty")
	}
	if a.Handle == "" {
		return 0, errors.New("autnum record handle cannot be empty")
	}
	if a.Number == 0 {
		return 0, errors.New("autnum record ASN cannot be zero")
	}
	if _, err := parseTimestamp(a.CreatedDate); err != nil {
		return 0, fmt.Errorf("autnum record must have a valid created date: %v", err)
	}
	if _, err := parseTimestamp(a.UpdatedDate); err != nil {
		return 0, fmt.Errorf("autnum record must have a valid updated date: %v", err)
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertAutnumRecordText, pgx.NamedArgs{"record": string(record)}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.pool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchAutnumRecordByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var rid int64
	var c, u time.Time
	var attrsJSON string
	var a oamreg.AutnumRecord

	j := NewRowJob(ctx, selectAutnumByIDText, pgx.NamedArgs{"row_id": rowID}, func(row pgx.Row) error {
		return row.Scan(&rid, &c, &u, &a.Handle, &a.Number, &a.Name, &a.WhoisServer, &attrsJSON)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	e, err := r.buildAutnumRecordEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findAutnumRecordsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	j := NewRowsJob(ctx, selectAutnumFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamreg.AutnumRecord

			if err := rows.Scan(&eid, &rid, &c, &u, &a.Handle,
				&a.Number, &a.Name, &a.WhoisServer, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildAutnumRecordEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) getAutnumRecordsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectAutnumSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamreg.AutnumRecord

			if err := rows.Scan(&eid, &rid, &c, &u, &a.Handle,
				&a.Number, &a.Name, &a.WhoisServer, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildAutnumRecordEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) buildAutnumRecordEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamreg.AutnumRecord) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no autnum record found")
	}
	if a.Name == "" {
		return nil, errors.New("autnum record name is missing")
	}
	if a.Handle == "" {
		return nil, errors.New("autnum record handle is missing")
	}
	if a.Number == 0 {
		return nil, errors.New("autnum record ASN is missing")
	}

	var attrs autnumAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Raw = attrs.Raw
	a.Status = attrs.Status
	a.CreatedDate = attrs.CreatedDate
	a.UpdatedDate = attrs.UpdatedDate

	if _, err := parseTimestamp(a.CreatedDate); err != nil {
		return nil, fmt.Errorf("autnum record created date is missing or invalid: %v", err)
	}
	if _, err := parseTimestamp(a.UpdatedDate); err != nil {
		return nil, fmt.Errorf("autnum record updated date is missing or invalid: %v", err)
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
