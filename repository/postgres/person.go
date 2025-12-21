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
	"github.com/owasp-amass/open-asset-model/people"
)

// Params: @record::jsonb
const upsertPersonText = `SELECT public.person_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectPersonByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.full_name, a.unique_id, a.first_name, a.family_name, a.attrs
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
	if a.FirstName == "" && a.FamilyName == "" {
		return 0, fmt.Errorf("the person %s does not have a first or family name", a.FullName)
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.person.upsert",
		SQLText: upsertPersonText,
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

func (r *PostgresRepository) fetchPersonByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.person.by_id",
		SQLText: selectPersonByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var rid int64
	var c, u time.Time
	var a people.Person
	var attrsJSON string
	if err := result.Row.Scan(&rid, &c, &u, &a.FullName,
		&a.ID, &a.FirstName, &a.FamilyName, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildPersonEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findPersonsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
		Name:    "asset.person.find_by_content",
		SQLText: selectPersonFindByContentText,
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
		var a people.Person
		var attrsJSON string

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.ID,
			&a.FullName, &a.FirstName, &a.FamilyName, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildPersonEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
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

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.person.updated_since",
		SQLText: selectPersonSinceText,
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
		var a people.Person
		var attrsJSON string

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.ID,
			&a.FullName, &a.FirstName, &a.FamilyName, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildPersonEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildPersonEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *people.Person) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("person not found")
	}
	if a.FullName == "" {
		return nil, errors.New("person full name is missing")
	}
	if a.FirstName == "" && a.FamilyName == "" {
		return nil, errors.New("person first and family names are missing")
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
