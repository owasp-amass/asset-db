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
	"github.com/owasp-amass/asset-db/types"
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

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.autnum.upsert",
		SQLText: upsertAutnumRecordText,
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

func (r *PostgresRepository) fetchAutnumRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.autnum.by_id",
		SQLText: selectAutnumByIDText,
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
	var a oamreg.AutnumRecord
	if err := result.Row.Scan(&rid, &c, &u, &a.Handle,
		&a.Number, &a.Name, &a.WhoisServer, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildAutnumRecordEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findAutnumRecordsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
		Name:    "asset.autnum.find_by_content",
		SQLText: selectAutnumFindByContentText,
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
		var a oamreg.AutnumRecord

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.Handle,
			&a.Number, &a.Name, &a.WhoisServer, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildAutnumRecordEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getAutnumRecordsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*types.Entity, error) {
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
		Name:    "asset.autnum.updated_since",
		SQLText: selectAutnumSinceText,
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
		var a oamreg.AutnumRecord

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.Handle,
			&a.Number, &a.Name, &a.WhoisServer, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildAutnumRecordEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildAutnumRecordEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamreg.AutnumRecord) (*types.Entity, error) {
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

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
