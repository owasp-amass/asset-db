// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// PHONE ----------------------------------------------------------------------
// Params: :raw_number, :e164, :number_type, :country_code, :country_abbrev, :attrs
const tmplUpsertPhone = `
WITH
  row_try AS (
    INSERT INTO phone(raw_number, e164, number_type, country_code, country_abbrev)
    VALUES (:raw_number, :e164, :number_type, :country_code, :country_abbrev)
    ON CONFLICT(e164) DO UPDATE SET
      raw_number     = COALESCE(excluded.raw_number,     phone.raw_number),
      number_type    = COALESCE(excluded.number_type,    phone.number_type),
      country_code   = COALESCE(excluded.country_code,   phone.country_code),
      country_abbrev = COALESCE(excluded.country_abbrev, phone.country_abbrev),
      updated_at     = CASE WHEN
        (excluded.raw_number     IS NOT phone.raw_number) OR
        (excluded.number_type    IS NOT phone.number_type) OR
        (excluded.country_code   IS NOT phone.country_code) OR
        (excluded.country_abbrev IS NOT phone.country_abbrev)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE phone.updated_at END
    WHERE (excluded.raw_number     IS NOT phone.raw_number) OR
          (excluded.number_type    IS NOT phone.number_type) OR
          (excluded.country_code   IS NOT phone.country_code) OR
          (excluded.country_abbrev IS NOT phone.country_abbrev)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM phone WHERE e164=:e164 LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('phone') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='phone' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :e164, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:e164 LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'phone',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

type Phone struct {
	ID            int64      `json:"id"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	RawNumber     string     `json:"raw_number"`
	E164          string     `json:"e164"`
	NumberType    *string    `json:"number_type,omitempty"`
	CountryCode   *int64     `json:"country_code,omitempty"`
	CountryAbbrev *string    `json:"country_abbrev,omitempty"`
}

func (s *Statements) UpsertPhone(ctx context.Context, phone *Phone, attrsJSON string) (int64, error) {
	row := s.UpsertPhoneStmt.QueryRowContext(ctx,
		sql.Named("raw_number", phone.RawNumber),
		sql.Named("e164", phone.E164),
		sql.Named("number_type", phone.NumberType),
		sql.Named("country_code", phone.CountryCode),
		sql.Named("country_abbrev", phone.CountryAbbrev),
		sql.Named("attrs", attrsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchPhoneByRowID(ctx context.Context, rowID int64) (*Phone, error) {
	query := `SELECT id, created_at, updated_at, raw_number, e164, number_type, country_code, country_abbrev
		      FROM phone WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "phone", query)
	if err != nil {
		return nil, err
	}

	var a Phone
	var c, u *string
	var cc *int64
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.RawNumber, &a.E164, &a.NumberType, &cc, &a.CountryAbbrev,
	); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	a.CountryCode = cc
	return &a, nil
}
