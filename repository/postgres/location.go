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
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: @record::jsonb
const upsertLocationText = `SELECT public.location_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectLocationByID = `
SELECT a.id, a.created_at, a.updated_at, a.city, a.unit, a.street_address, a.country, 
	   a.building, a.province, a.locality, a.postal_code, a.street_name, a.building_number, a.attrs
FROM public.location_get_by_id(@row_id::bigint) AS a;`

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

func (r *PostgresRepository) fetchLocationByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.location.by_id",
		SQLText: selectLocationByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a contact.Location
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.City, &a.Unit,
		&a.Address, &a.Country, &a.Building, &a.Province, &a.Locality,
		&a.PostalCode, &a.StreetName, &a.BuildingNumber, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no location found")
	}
	if a.Address == "" {
		return nil, errors.New("location street address is missing")
	}
	if a.City == "" {
		return nil, errors.New("location city is missing")
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

	var attrs locationAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.POBox = attrs.POBox
	a.GLN = attrs.GLN

	return e, nil
}
