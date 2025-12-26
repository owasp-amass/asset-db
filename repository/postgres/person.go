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
	"github.com/owasp-amass/open-asset-model/people"
)

// Params: @record::jsonb
const upsertPersonText = `SELECT public.person_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectPersonByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.full_name, a.first_name, a.family_name, a.attrs
FROM public.person_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectPersonFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.full_name, a.first_name, a.family_name, a.attrs 
FROM public.person_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectPersonSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.full_name, a.first_name, a.family_name, a.attrs 
FROM public.person_updated_since(@since::timestamp, @limit::integer) AS a;`

type personAttributes struct {
	MiddleName string `json:"middle_name,omitempty"`
	BirthDate  string `json:"birth_date,omitempty"`
	Gender     string `json:"gender,omitempty"`
}

func (r *PostgresRepository) upsertPerson(ctx context.Context, a *people.Person) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid person provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("the person %s does not have a unique ID", a.FullName)
	}
	if a.FullName == "" {
		return 0, fmt.Errorf("the person %s does not have a full name", a.FullName)
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertPersonText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.pool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchPersonByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var rid int64
	var c, u time.Time
	var a people.Person
	var attrsJSON string
	var full, first, family pgtype.Text

	j := NewRowJob(ctx, selectPersonByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(&rid, &c, &u, &a.ID, &full, &first, &family, &attrsJSON)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	if full.Valid {
		a.FullName = full.String
	}
	if first.Valid {
		a.FirstName = first.String
	}
	if family.Valid {
		a.FamilyName = family.String
	}

	e, err := r.buildPersonEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findPersonsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	j := NewRowsJob(ctx, selectPersonFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var a people.Person
			var attrsJSON string
			var full, first, family pgtype.Text

			if err := rows.Scan(&eid, &rid, &c, &u, &a.ID, &full, &first, &family, &attrsJSON); err != nil {
				continue
			}
			if full.Valid {
				a.FullName = full.String
			}
			if first.Valid {
				a.FirstName = first.String
			}
			if family.Valid {
				a.FamilyName = family.String
			}

			if ent, err := r.buildPersonEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) getPersonsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectPersonSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var a people.Person
			var attrsJSON string
			var full, first, family pgtype.Text

			if err := rows.Scan(&eid, &rid, &c, &u, &a.ID, &full, &first, &family, &attrsJSON); err != nil {
				continue
			}
			if full.Valid {
				a.FullName = full.String
			}
			if first.Valid {
				a.FirstName = first.String
			}
			if family.Valid {
				a.FamilyName = family.String
			}

			if ent, err := r.buildPersonEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
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

func (r *PostgresRepository) buildPersonEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *people.Person) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("person not found")
	}
	if a.ID == "" {
		return nil, errors.New("person unique ID is missing")
	}
	if a.FullName == "" {
		return nil, errors.New("person full name is missing")
	}

	var attrs personAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.MiddleName = attrs.MiddleName
	a.BirthDate = attrs.BirthDate
	a.Gender = attrs.Gender

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
