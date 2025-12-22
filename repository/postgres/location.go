// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: @record::jsonb
const upsertLocationText = `SELECT public.location_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectLocationByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.city, a.unit, a.street_address, a.country, 
	   a.building, a.province, a.locality, a.postal_code, a.street_name, a.building_number, a.attrs
FROM public.location_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectLocationFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.street_address, a.city, a.country, a.unit, a.building, a.province, a.locality, a.postal_code, a.street_name, a.building_number, a.attrs
FROM public.location_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectLocationSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.street_address, a.city, a.country, a.unit, a.building, a.province, a.locality, a.postal_code, a.street_name, a.building_number, a.attrs
FROM public.location_updated_since(@since::timestamp, @limit::integer) AS a;`

type locationAttributes struct {
	POBox string `json:"po_box,omitempty"`
	GLN   int    `json:"gln,omitempty"`
}

func (r *PostgresRepository) upsertLocation(ctx context.Context, a *contact.Location) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid location provided")
	}
	if a.Address == "" {
		return 0, errors.New("location street address cannot be empty")
	}
	if a.City == "" {
		return 0, errors.New("location city cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.location.upsert",
		SQLText: upsertLocationText,
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

func (r *PostgresRepository) fetchLocationByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.location.by_id",
		SQLText: selectLocationByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var rid int64
	var c, u time.Time
	var attrsJSON string
	var a contact.Location
	if err := result.Row.Scan(&rid, &c, &u, &a.City, &a.Unit,
		&a.Address, &a.Country, &a.Building, &a.Province, &a.Locality,
		&a.PostalCode, &a.StreetName, &a.BuildingNumber, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildLocationEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findLocationsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
		Name:    "asset.location.find_by_content",
		SQLText: selectLocationFindByContentText,
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
		var attrsJSON string
		var a contact.Location

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.Address, &a.City,
			&a.Country, &a.Unit, &a.Building, &a.Province, &a.Locality,
			&a.PostalCode, &a.StreetName, &a.BuildingNumber, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildLocationEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getLocationsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
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
		Name:    "asset.location.updated_since",
		SQLText: selectLocationSinceText,
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
		var attrsJSON string
		var a contact.Location

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.Address, &a.City,
			&a.Country, &a.Unit, &a.Building, &a.Province, &a.Locality,
			&a.PostalCode, &a.StreetName, &a.BuildingNumber, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildLocationEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildLocationEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *contact.Location) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no location found")
	}
	if a.Address == "" {
		return nil, errors.New("location street address is missing")
	}
	if a.City == "" {
		return nil, errors.New("location city is missing")
	}

	var attrs locationAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.POBox = attrs.POBox
	a.GLN = attrs.GLN

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
