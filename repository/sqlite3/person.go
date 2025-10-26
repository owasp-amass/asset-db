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

// PERSON ---------------------------------------------------------------------
// Params: :unique_id, :full_name, :first_name, :family_name, :middle_name, :attrs
const tmplUpsertPerson = `
WITH
  row_try AS (
    INSERT INTO person(unique_id, full_name, first_name, family_name, middle_name)
    VALUES (:unique_id, :full_name, :first_name, :family_name, :middle_name)
    ON CONFLICT(unique_id) DO UPDATE SET
      full_name   = COALESCE(excluded.full_name,   person.full_name),
      first_name  = COALESCE(excluded.first_name,  person.first_name),
      family_name = COALESCE(excluded.family_name, person.family_name),
      middle_name = COALESCE(excluded.middle_name, person.middle_name),
      updated_at  = CASE WHEN
        (excluded.full_name   IS NOT person.full_name) OR
        (excluded.first_name  IS NOT person.first_name) OR
        (excluded.family_name IS NOT person.family_name) OR
        (excluded.middle_name IS NOT person.middle_name)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE person.updated_at END
    WHERE (excluded.full_name   IS NOT person.full_name) OR
          (excluded.first_name  IS NOT person.first_name) OR
          (excluded.family_name IS NOT person.family_name) OR
          (excluded.middle_name IS NOT person.middle_name)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM person WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('person') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='person' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), COALESCE(:full_name,:unique_id), coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=COALESCE(:full_name,:unique_id) LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'person',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

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

func (s *Statements) UpsertPerson(ctx context.Context, a *people.Person) (int64, error) {
	row := s.UpsertPersonStmt.QueryRowContext(ctx,
		sql.Named("full_name", a.FullName),
		sql.Named("unique_id", a.ID),
		sql.Named("first_name", a.FirstName),
		sql.Named("family_name", a.FamilyName),
		sql.Named("middle_name", a.MiddleName),
		sql.Named("attrs", "{}"),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchPersonByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, full_name, unique_id, first_name, family_name, middle_name
		      FROM person WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "person", query)
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
		CreatedAt: (*a.CreatedAt).In(time.UTC).Local(),
		LastSeen:  (*a.UpdatedAt).In(time.UTC).Local(),
		Asset: &people.Person{
			ID:         a.UniqueID,
			FullName:   fullname,
			FirstName:  firstname,
			FamilyName: familyname,
			MiddleName: middlename,
		},
	}, nil
}
