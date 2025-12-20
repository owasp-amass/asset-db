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
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: @record::jsonb
const upsertPhoneText = `SELECT public.phone_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectPhoneByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.e164, a.country_code, a.attrs
FROM public.phone_get_by_id(@row_id::bigint) AS a;`

type phoneAttributes struct {
	Raw           string `json:"raw,omitempty"`
	Type          string `json:"type,omitempty"`
	Extension     string `json:"ext,omitempty"`
	CountryAbbrev string `json:"country_abbrev,omitempty"`
}

func (r *PostgresRepository) upsertPhone(ctx context.Context, a *contact.Phone) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid phone provided")
	}
	if a.Raw == "" {
		return 0, fmt.Errorf("the phone number is not provided in raw format")
	}
	if a.E164 == "" {
		return 0, fmt.Errorf("the phone number %s does not have an E.164 format", a.Raw)
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.phone.upsert",
		SQLText: upsertPhoneText,
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

func (r *PostgresRepository) fetchPhoneByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.phone.by_id",
		SQLText: selectPhoneByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
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
