// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
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
    updated_at  = CURRENT_TIMESTAMP;`

// Param: :unique_id
const selectEntityIDByPersonText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'person' LIMIT 1)
  AND display_value = :unique_id
LIMIT 1;`

// Param: :row_id
const selectPersonByIDText = `
SELECT id, created_at, updated_at, full_name, unique_id, first_name, family_name, middle_name 
FROM person 
WHERE id = :row_id
LIMIT 1;`

type person struct {
	ID         int64      `json:"id"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	FullName   *string    `json:"full_name,omitempty"`
	UniqueID   string     `json:"unique_id"`
	FirstName  *string    `json:"first_name,omitempty"`
	FamilyName *string    `json:"family_name,omitempty"`
	MiddleName *string    `json:"middle_name,omitempty"`
}

func (r *SqliteRepository) upsertPerson(ctx context.Context, a *people.Person) (int64, error) {
	const keySel = "asset.person.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertPersonText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("full_name", a.FullName),
		sql.Named("unique_id", a.ID),
		sql.Named("first_name", a.FirstName),
		sql.Named("family_name", a.FamilyName),
		sql.Named("middle_name", a.MiddleName),
	)

	const keySel2 = "asset.person.entity_id_by_person"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByPersonText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("unique_id", a.ID)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchPersonByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.fqdn.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectPersonByIDText)
	if err != nil {
		return nil, err
	}

	var a person
	var c, u *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.FullName, &a.UniqueID, &a.FirstName, &a.FamilyName, &a.MiddleName,
	); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	if a.CreatedAt == nil || a.UpdatedAt == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var fullname, firstname, familyname, middlename string
	if a.FullName != nil {
		fullname = *a.FullName
	}
	if a.FirstName != nil {
		firstname = *a.FirstName
	}
	if a.FamilyName != nil {
		familyname = *a.FamilyName
	}
	if a.MiddleName != nil {
		middlename = *a.MiddleName
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: a.CreatedAt.In(time.UTC).Local(),
		LastSeen:  a.UpdatedAt.In(time.UTC).Local(),
		Asset: &people.Person{
			ID:         a.UniqueID,
			FullName:   fullname,
			FirstName:  firstname,
			FamilyName: familyname,
			MiddleName: middlename,
		},
	}, nil
}
