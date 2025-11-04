// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/people"
)

// Params: :unique_id, :full_name, :first_name, :family_name, :middle_name
const upsertPersonText = `
INSERT INTO person(unique_id, full_name, first_name, family_name, middle_name)
VALUES (:unique_id, :full_name, :first_name, :family_name, :middle_name)
ON CONFLICT(unique_id) DO UPDATE SET
    full_name   = COALESCE(excluded.full_name,   person.full_name),
    first_name  = COALESCE(excluded.first_name,  person.first_name),
    family_name = COALESCE(excluded.family_name, person.family_name),
    middle_name = COALESCE(excluded.middle_name, person.middle_name),
    updated_at  = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByPersonText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'person' LIMIT 1)
  AND natural_key = :unique_id
LIMIT 1`

// Param: :row_id
const selectPersonByIDText = `
SELECT id, created_at, updated_at, full_name, unique_id, first_name, family_name, middle_name 
FROM person 
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertPerson(ctx context.Context, a *people.Person) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.person.upsert",
		SQLText: upsertPersonText,
		Args: []any{
			sql.Named("full_name", a.FullName),
			sql.Named("unique_id", a.ID),
			sql.Named("first_name", a.FirstName),
			sql.Named("family_name", a.FamilyName),
			sql.Named("middle_name", a.MiddleName),
		},
		Result: done,
	})
	err := <-done
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

	var c, u string
	var row_id int64
	var a people.Person
	if err := result.Row.Scan(&row_id, &c, &u, &a.FullName, &a.ID,
		&a.FirstName, &a.FamilyName, &a.MiddleName); err != nil {
		return nil, err
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

	return e, nil
}
