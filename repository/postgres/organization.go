// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// Params: @record::jsonb
const upsertOrganizationText = `SELECT public.organization_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectOrganizationByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.org_name, a.legal_name, a.jurisdiction, a.registration_id, a.attrs
FROM public.organization_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectOrganizationFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.org_name, a.legal_name, a.jurisdiction, a.registration_id, a.attrs 
FROM public.organization_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectOrganizationSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.org_name, a.legal_name, a.jurisdiction, a.registration_id, a.attrs 
FROM public.organization_updated_since(@since::timestamp, @limit::integer) AS a;`

type organizationAttributes struct {
	FoundingDate  string   `json:"founding_date,omitempty"`
	Industry      string   `json:"industry,omitempty"`
	TargetMarkets []string `json:"target_markets,omitempty"`
	Active        bool     `json:"active"`
	NonProfit     bool     `json:"non_profit,omitempty"`
	Headcount     int      `json:"headcount,omitempty"`
}

func (r *PostgresRepository) upsertOrganization(ctx context.Context, a *oamorg.Organization) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid organization provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("the organization ID cannot be empty")
	}
	if a.Name == "" {
		return 0, fmt.Errorf("the organization name cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertOrganizationText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.pool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchOrganizationByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var row_id int64
	var c, u time.Time
	var attrsJSON string
	var a oamorg.Organization
	var legal, jurisdiction, registration pgtype.Text

	j := NewRowJob(ctx, selectOrganizationByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(&row_id, &c, &u, &a.ID, &a.Name, &legal, &jurisdiction, &registration, &attrsJSON)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	if legal.Valid {
		a.LegalName = legal.String
	}
	if jurisdiction.Valid {
		a.Jurisdiction = jurisdiction.String
	}
	if registration.Valid {
		a.RegistrationID = registration.String
	}

	e, err := r.buildOrganizationEntity(eid, row_id, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findOrganizationsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	j := NewRowsJob(ctx, selectOrganizationFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamorg.Organization
			var legal, jurisdiction, registration pgtype.Text

			if err := rows.Scan(&eid, &rid, &c, &u, &a.ID,
				&a.Name, &legal, &jurisdiction, &registration, &attrsJSON); err != nil {
				continue
			}
			if legal.Valid {
				a.LegalName = legal.String
			}
			if jurisdiction.Valid {
				a.Jurisdiction = jurisdiction.String
			}
			if registration.Valid {
				a.RegistrationID = registration.String
			}

			if ent, err := r.buildOrganizationEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) getOrganizationsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectOrganizationSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamorg.Organization
			var legal, jurisdiction, registration pgtype.Text

			if err := rows.Scan(&eid, &rid, &c, &u, &a.ID,
				&a.Name, &legal, &jurisdiction, &registration, &attrsJSON); err != nil {
				continue
			}
			if legal.Valid {
				a.LegalName = legal.String
			}
			if jurisdiction.Valid {
				a.Jurisdiction = jurisdiction.String
			}
			if registration.Valid {
				a.RegistrationID = registration.String
			}

			if ent, err := r.buildOrganizationEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) buildOrganizationEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamorg.Organization) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no organization found")
	}
	if a.Name == "" {
		return nil, errors.New("organization name is missing")
	}

	var attrs organizationAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.FoundingDate = attrs.FoundingDate
	a.Industry = attrs.Industry
	a.TargetMarkets = attrs.TargetMarkets
	a.Active = attrs.Active
	a.NonProfit = attrs.NonProfit
	a.Headcount = attrs.Headcount

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
