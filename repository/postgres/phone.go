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
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: @record::jsonb
const upsertPhoneText = `SELECT public.phone_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectPhoneByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.e164, a.country_code, a.attrs
FROM public.phone_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectPhoneFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.e164, a.country_code, a.attrs 
FROM public.phone_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectPhoneSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.e164, a.country_code, a.attrs 
FROM public.phone_updated_since(@since::timestamp, @limit::integer) AS a;`

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

func (r *PostgresRepository) fetchPhoneByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
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

	var rid int64
	var c, u time.Time
	var a contact.Phone
	var attrsJSON string
	if err := result.Row.Scan(&rid, &c, &u, &a.E164, &a.CountryCode, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildPhoneEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findPhonesByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
	if !since.IsZero() {
		since = since.UTC()
	}
	ts := zeronull.Timestamp(since)

	if len(filters) == 0 {
		return nil, errors.New("no filters provided")
	}

	filtersJSON, err := json.Marshal(filters)
	if err != nil {
		return nil, err
	}

	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.phone.find_by_content",
		SQLText: selectPhoneFindByContentText,
		Args: pgx.NamedArgs{
			"filters": string(filtersJSON),
			"since":   ts,
			"limit":   limit,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid, rid int64
		var c, u time.Time
		var a contact.Phone
		var attrsJSON string

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.E164, &a.CountryCode, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildPhoneEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getPhonesUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.phone.updated_since",
		SQLText: selectPhoneSinceText,
		Args: pgx.NamedArgs{
			"since": since.UTC(),
			"limit": lmt,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid, rid int64
		var c, u time.Time
		var a contact.Phone
		var attrsJSON string

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.E164, &a.CountryCode, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildPhoneEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildPhoneEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *contact.Phone) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, fmt.Errorf("no phone record found with row ID %d", rid)
	}
	if a.E164 == "" {
		return nil, fmt.Errorf("phone record with row ID %d is missing E.164 format", rid)
	}

	var attrs phoneAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Raw = attrs.Raw
	a.Type = attrs.Type
	a.CountryAbbrev = attrs.CountryAbbrev

	if a.Raw == "" {
		return nil, fmt.Errorf("phone with row ID %d is missing raw format", rid)
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
