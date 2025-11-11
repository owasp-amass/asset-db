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
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: :raw_number, :e164, :number_type, :country_code, :country_abbrev
const upsertPhoneText = `
INSERT INTO phone(raw_number, e164, number_type, country_code, country_abbrev)
VALUES (:raw_number, :e164, :number_type, :country_code, :country_abbrev)
ON CONFLICT(e164) DO UPDATE SET
    raw_number     = COALESCE(excluded.raw_number,     phone.raw_number),
    number_type    = COALESCE(excluded.number_type,    phone.number_type),
    country_code   = COALESCE(excluded.country_code,   phone.country_code),
    country_abbrev = COALESCE(excluded.country_abbrev, phone.country_abbrev),
    updated_at     = CURRENT_TIMESTAMP`

// Param: :e164
const selectEntityIDByPhoneText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'phone' LIMIT 1)
  AND natural_key = :e164
LIMIT 1`

// Param: :row_id
const selectPhoneByIDText = `
SELECT id, created_at, updated_at, raw_number, e164, number_type, country_code, country_abbrev 
FROM phone
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertPhone(ctx context.Context, a *contact.Phone) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.phone.upsert",
		SQLText: upsertPhoneText,
		Args: []any{
			sql.Named("raw_number", a.Raw),
			sql.Named("e164", a.E164),
			sql.Named("number_type", a.Type),
			sql.Named("country_code", a.CountryCode),
			sql.Named("country_abbrev", a.CountryAbbrev),
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
		Name:    "asset.phone.entity_id_by_phone",
		SQLText: selectEntityIDByPhoneText,
		Args:    []any{sql.Named("e164", a.E164)},
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

func (r *SqliteRepository) fetchPhoneByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.phone.by_id",
		SQLText: selectPhoneByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var c, u string
	var row_id int64
	var a contact.Phone
	if err := result.Row.Scan(&row_id, &c, &u, &a.Raw, &a.E164, &a.Type, &a.CountryCode, &a.CountryAbbrev); err != nil {
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
