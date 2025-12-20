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
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/people"
)

// Params: @record::jsonb
const upsertPersonText = `SELECT public.person_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectPersonByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.full_name, a.unique_id, a.first_name, a.family_name, a.attrs
FROM public.person_get_by_id(@row_id::bigint) AS a;`

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

func (r *PostgresRepository) fetchPersonByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
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

	var row_id int64
	var a people.Person
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.FullName,
		&a.ID, &a.FirstName, &a.FamilyName, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("person not found")
	}
	if a.FullName == "" {
		return nil, errors.New("person full name is missing")
	}
	if a.FirstName == "" && a.FamilyName == "" {
		return nil, errors.New("person first and family names are missing")
	}

	e := &types.Entity{ID: strconv.FormatInt(eid, 10), Asset: &a}
	if created, err := parseTimestamp(c); err != nil {
		return nil, err
	} else {
		e.CreatedAt = created.In(time.UTC).Local()
	}
	if updated, err := parseTimestamp(u); err != nil {
		return nil, err
	} else {
		e.LastSeen = updated.In(time.UTC).Local()
	}

	var attrs personAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.MiddleName = attrs.MiddleName
	a.BirthDate = attrs.BirthDate
	a.Gender = attrs.Gender

	return e, nil
}
