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
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: :e164, :country_code, :attrs
const upsertPhoneText = `
INSERT INTO phone(e164, country_code, attrs)
VALUES (:e164, :country_code, :attrs)
ON CONFLICT(e164) DO UPDATE SET
    country_code   = COALESCE(excluded.country_code, phone.country_code),
    attrs          = json_patch(phone.attrs,         excluded.attrs),
    updated_at     = CURRENT_TIMESTAMP`

// Param: :e164
const selectEntityIDByPhoneText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'phone' LIMIT 1)
  AND natural_key = :e164
LIMIT 1`

// Param: :row_id
const selectPhoneByIDText = `
SELECT id, created_at, updated_at, e164, country_code, attrs
FROM phone
WHERE id = :row_id
LIMIT 1`

type phoneAttributes struct {
	Raw           string `json:"raw,omitempty"`
	Type          string `json:"type,omitempty"`
	Extension     string `json:"ext,omitempty"`
	CountryAbbrev string `json:"country_abbrev,omitempty"`
}

func (r *SqliteRepository) upsertPhone(ctx context.Context, a *contact.Phone) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid phone provided")
	}
	if a.Raw == "" {
		return 0, fmt.Errorf("the phone number is not provided in raw format")
	}
	if a.E164 == "" {
		return 0, fmt.Errorf("the phone number %s does not have an E.164 format", a.Raw)
	}

	attrs := phoneAttributes{
		Raw:           a.Raw,
		Type:          a.Type,
		Extension:     a.Ext,
		CountryAbbrev: a.CountryAbbrev,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.phone.upsert",
		SQLText: upsertPhoneText,
		Args: []any{
			sql.Named("e164", a.E164),
			sql.Named("country_code", a.CountryCode),
			sql.Named("attrs", attrsJSON),
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

	var row_id int64
	var a contact.Phone
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.E164, &a.CountryCode, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, fmt.Errorf("no phone record found with row ID %d", rowID)
	}
	if a.E164 == "" {
		return nil, fmt.Errorf("phone record with row ID %d is missing E.164 format", rowID)
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

	var attrs phoneAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Raw = attrs.Raw
	a.Type = attrs.Type
	a.CountryAbbrev = attrs.CountryAbbrev

	if a.Raw == "" {
		return nil, fmt.Errorf("phone with row ID %d is missing raw format", rowID)
	}

	return e, nil
}
