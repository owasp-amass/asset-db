// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/people"
)

// Params: :unique_id, :full_name, :first_name, :family_name, :middle_name, :attrs
const upsertPersonText = `
INSERT INTO person(unique_id, full_name, first_name, family_name, attrs)
VALUES (:unique_id, :full_name, :first_name, :family_name, :attrs)
ON CONFLICT(unique_id) DO UPDATE SET
    full_name   = COALESCE(excluded.full_name,   person.full_name),
    first_name  = COALESCE(excluded.first_name,  person.first_name),
    family_name = COALESCE(excluded.family_name, person.family_name),
    attrs       = COALESCE(excluded.attrs,       person.attrs),
    updated_at  = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByPersonText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'person' LIMIT 1)
  AND natural_key = :unique_id
LIMIT 1`

// Param: :row_id
const selectPersonByIDText = `
SELECT id, created_at, updated_at, full_name, unique_id, first_name, family_name, attrs
FROM person
WHERE id = :row_id
LIMIT 1`

type personAttributes struct {
	MiddleName string `json:"middle_name"`
	BirthDate  string `json:"birth_date"`
	Gender     string `json:"gender"`
}

func (r *SqliteRepository) upsertPerson(ctx context.Context, a *people.Person) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid person provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("the person %s does not have a unique ID", a.FullName)
	}
	if a.FirstName == "" && a.FamilyName == "" {
		return 0, fmt.Errorf("the person %s does not have a first or family name", a.FullName)
	}

	attrs := personAttributes{
		MiddleName: a.MiddleName,
		BirthDate:  a.BirthDate,
		Gender:     a.Gender,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.person.upsert",
		SQLText: upsertPersonText,
		Args: []any{
			sql.Named("unique_id", a.ID),
			sql.Named("full_name", a.FullName),
			sql.Named("first_name", a.FirstName),
			sql.Named("family_name", a.FamilyName),
			sql.Named("attrs", string(attrsJSON)),
		},
		Result: done,
	})
	err = <-done
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.person.entity_id_by_person",
		SQLText: selectEntityIDByPersonText,
		Args:    []any{sql.Named("unique_id", a.ID)},
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

func (r *SqliteRepository) fetchPersonByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.person.by_id",
		SQLText: selectPersonByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
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
