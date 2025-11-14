// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: :city, :street_address, :country, :unit, :building,
// :province, :locality, :postal_code, :street_name, :building_number, :attrs
const upsertLocationText = `
INSERT INTO location(city, street_address, country, unit, building, province, locality, postal_code, street_name, building_number, attrs)
VALUES (:city, :street_address, :country, :unit, :building, :province, :locality, :postal_code, :street_name, :building_number, :attrs)
ON CONFLICT(street_address_norm) DO UPDATE SET
    city            = COALESCE(excluded.city,            location.city),
    country         = COALESCE(excluded.country,         location.country),
    unit            = COALESCE(excluded.unit,            location.unit),
    building        = COALESCE(excluded.building,        location.building),
    province        = COALESCE(excluded.province,        location.province),
    locality        = COALESCE(excluded.locality,        location.locality),
    postal_code     = COALESCE(excluded.postal_code,     location.postal_code),
    street_name     = COALESCE(excluded.street_name,     location.street_name),
    building_number = COALESCE(excluded.building_number, location.building_number),
    attrs           = COALESCE(excluded.attrs,           location.attrs),
    updated_at      = CURRENT_TIMESTAMP`

// Param: :street_address
const selectEntityIDByLocationText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'location' LIMIT 1)
  AND natural_key = lower(:street_address)
LIMIT 1`

// Param: :row_id
const selectLocationByID = `
SELECT id, created_at, updated_at, city, unit, street_address, country, 
	   building, province, locality, postal_code, street_name, building_number, attrs
FROM location 
WHERE id = :row_id
LIMIT 1`

type locationAttributes struct {
	POBox string `json:"po_box"`
	GLN   int    `json:"gln"`
}

func (r *SqliteRepository) upsertLocation(ctx context.Context, a *contact.Location) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid location provided")
	}
	if a.Address == "" {
		return 0, errors.New("location street address cannot be empty")
	}
	if a.City == "" {
		return 0, errors.New("location city cannot be empty")
	}

	attrs := locationAttributes{
		POBox: a.POBox,
		GLN:   a.GLN,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.location.upsert",
		SQLText: upsertLocationText,
		Args: []any{
			sql.Named("city", a.City),
			sql.Named("unit", a.Unit),
			sql.Named("street_address", a.Address),
			sql.Named("country", a.Country),
			sql.Named("building", a.Building),
			sql.Named("province", a.Province),
			sql.Named("locality", a.Locality),
			sql.Named("postal_code", a.PostalCode),
			sql.Named("street_name", a.StreetName),
			sql.Named("building_number", a.BuildingNumber),
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
		Name:    "asset.location.entity_id_by_location",
		SQLText: selectEntityIDByLocationText,
		Args:    []any{sql.Named("street_address", a.Address)},
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

func (r *SqliteRepository) fetchLocationByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.location.by_id",
		SQLText: selectLocationByID,
		Args:    []any{sql.Named("row_id", rowID)},
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
