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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Params: @record::jsonb
const upsertDomainRecordText = `SELECT public.domainrecord_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectDomainRecordByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.domain, a.record_name, a.punycode, a.extension, a.whois_server, a.object_id, a.attrs
FROM public.domainrecord_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectDomainRecordFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.domain, a.record_name, a.punycode, a.extension, a.whois_server, a.object_id, a.attrs 
FROM public.domainrecord_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectDomainRecordSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.domain, a.record_name, a.punycode, a.extension, a.whois_server, a.object_id, a.attrs 
FROM public.domainrecord_updated_since(@since::timestamp, @limit::integer) AS a;`

type domainRecordAttributes struct {
	Raw            string   `json:"raw,omitempty"`
	Status         []string `json:"status,omitempty"`
	CreatedDate    string   `json:"created_date,omitempty"`
	UpdatedDate    string   `json:"updated_date,omitempty"`
	ExpirationDate string   `json:"expiration_date,omitempty"`
	DNSSEC         bool     `json:"dnssec"`
}

func (r *PostgresRepository) upsertDomainRecord(ctx context.Context, a *oamreg.DomainRecord) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid domain record provided")
	}
	if a.Domain == "" {
		return 0, errors.New("domain record domain cannot be empty")
	}
	if a.Name == "" {
		return 0, errors.New("domain record name cannot be empty")
	}
	if a.Punycode == "" {
		return 0, errors.New("domain record punycode cannot be empty")
	}
	if a.Extension == "" {
		return 0, errors.New("domain record extension cannot be empty")
	}
	if _, err := parseTimestamp(a.CreatedDate); err != nil {
		return 0, fmt.Errorf("domain record must have a valid created date: %v", err)
	}
	if _, err := parseTimestamp(a.UpdatedDate); err != nil {
		return 0, fmt.Errorf("domain record must have a valid updated date: %v", err)
	}
	if _, err := parseTimestamp(a.ExpirationDate); err != nil {
		return 0, fmt.Errorf("domain record must have a valid expiration date: %v", err)
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertDomainRecordText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.pool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchDomainRecordByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var rid int64
	var c, u time.Time
	var attrsJSON string
	var a oamreg.DomainRecord
	var puny, ext, whois, objectid pgtype.Text

	j := NewRowJob(ctx, selectDomainRecordByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(&rid, &c, &u, &a.Domain,
			&a.Name, &puny, &ext, &whois, &objectid, &attrsJSON)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	if puny.Valid {
		a.Punycode = puny.String
	}
	if ext.Valid {
		a.Extension = ext.String
	}
	if whois.Valid {
		a.WhoisServer = whois.String
	}
	if objectid.Valid {
		a.ID = objectid.String
	}

	e, err := r.buildDomainRecordEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}

	return e, nil
}

func (r *PostgresRepository) findDomainRecordsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	j := NewRowsJob(ctx, selectDomainRecordFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamreg.DomainRecord
			var puny, ext, whois, objectid pgtype.Text

			if err := rows.Scan(&eid, &rid, &c, &u, &a.Domain, &a.Name,
				&puny, &ext, &whois, &objectid, &attrsJSON); err != nil {
				continue
			}
			if puny.Valid {
				a.Punycode = puny.String
			}
			if ext.Valid {
				a.Extension = ext.String
			}
			if whois.Valid {
				a.WhoisServer = whois.String
			}
			if objectid.Valid {
				a.ID = objectid.String
			}

			if ent, err := r.buildDomainRecordEntity(
				eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) getDomainRecordsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectDomainRecordSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamreg.DomainRecord
			var puny, ext, whois, objectid pgtype.Text

			if err := rows.Scan(&eid, &rid, &c, &u, &a.Domain, &a.Name,
				&puny, &ext, &whois, &objectid, &attrsJSON); err != nil {
				continue
			}
			if puny.Valid {
				a.Punycode = puny.String
			}
			if ext.Valid {
				a.Extension = ext.String
			}
			if whois.Valid {
				a.WhoisServer = whois.String
			}
			if objectid.Valid {
				a.ID = objectid.String
			}

			if ent, err := r.buildDomainRecordEntity(
				eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) buildDomainRecordEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamreg.DomainRecord) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no domain record found")
	}
	if a.Domain == "" {
		return nil, errors.New("domain record domain is missing")
	}
	if a.Name == "" {
		return nil, errors.New("domain record name is missing")
	}
	if a.Punycode == "" {
		return nil, errors.New("domain record punycode is missing")
	}
	if a.Extension == "" {
		return nil, errors.New("domain record extension is missing")
	}
	if a.WhoisServer == "" {
		return nil, errors.New("domain record whois server is missing")
	}

	var attrs domainRecordAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Raw = attrs.Raw
	a.Status = attrs.Status
	a.CreatedDate = attrs.CreatedDate
	a.UpdatedDate = attrs.UpdatedDate
	a.ExpirationDate = attrs.ExpirationDate
	a.DNSSEC = attrs.DNSSEC

	if _, err := parseTimestamp(a.CreatedDate); err != nil {
		return nil, fmt.Errorf("domain record created date is missing or invalid: %v", err)
	}
	if _, err := parseTimestamp(a.UpdatedDate); err != nil {
		return nil, fmt.Errorf("domain record updated date is missing or invalid: %v", err)
	}
	if _, err := parseTimestamp(a.ExpirationDate); err != nil {
		return nil, fmt.Errorf("domain record expiration date is missing or invalid: %v", err)
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
