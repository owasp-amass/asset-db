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
    updated_at     = CURRENT_TIMESTAMP;`

// Param: :e164
const selectEntityIDByPhoneText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'phone' LIMIT 1)
  AND display_value = :e164
LIMIT 1;`

// Param: :row_id
const selectPhoneByIDText = `
SELECT id, created_at, updated_at, raw_number, e164, number_type, country_code, country_abbrev 
FROM phone
WHERE id = :row_id
LIMIT 1;`

type phone struct {
	ID            int64      `json:"id"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	RawNumber     string     `json:"raw_number"`
	E164          string     `json:"e164"`
	NumberType    *string    `json:"number_type,omitempty"`
	CountryCode   *int64     `json:"country_code,omitempty"`
	CountryAbbrev *string    `json:"country_abbrev,omitempty"`
}

func (r *SqliteRepository) upsertPhone(ctx context.Context, a *contact.Phone) (int64, error) {
	const keySel = "asset.phone.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertPhoneText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("raw_number", a.Raw),
		sql.Named("e164", a.E164),
		sql.Named("number_type", a.Type),
		sql.Named("country_code", a.CountryCode),
		sql.Named("country_abbrev", a.CountryAbbrev),
	)

	const keySel2 = "asset.phone.entity_id_by_phone"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByPhoneText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("e164", a.E164)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchPhoneByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.phone.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectPhoneByIDText)
	if err != nil {
		return nil, err
	}

	var a phone
	var c, u *string
	var cc *int64
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.RawNumber, &a.E164, &a.NumberType, &cc, &a.CountryAbbrev,
	); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	if a.CreatedAt == nil || a.UpdatedAt == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var ccode int
	if cc != nil {
		ccode = int(*cc)
	}

	var ntype, cabbrev string
	if a.NumberType != nil {
		ntype = *a.NumberType
	}
	if a.CountryAbbrev != nil {
		cabbrev = *a.CountryAbbrev
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: a.CreatedAt.In(time.UTC).Local(),
		LastSeen:  a.UpdatedAt.In(time.UTC).Local(),
		Asset: &contact.Phone{
			Raw:           a.RawNumber,
			E164:          a.E164,
			Type:          ntype,
			CountryCode:   ccode,
			CountryAbbrev: cabbrev,
		},
	}, nil
}
