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

// Params: :city, :street_address, :country, :unit, :building,
// :province, :locality, :postal_code, :street_name, :building_number
const upsertLocationText = `
INSERT INTO location(city, street_address, country, unit, building, province, locality, postal_code, street_name, building_number)
VALUES (:city, lower(:street_address), :country, :unit, :building, :province, :locality, :postal_code, :street_name, :building_number)
ON CONFLICT(street_address) DO UPDATE SET
    city            = COALESCE(excluded.city,            location.city),
    country         = COALESCE(excluded.country,         location.country),
    unit            = COALESCE(excluded.unit,            location.unit),
    building        = COALESCE(excluded.building,        location.building),
    province        = COALESCE(excluded.province,        location.province),
    locality        = COALESCE(excluded.locality,        location.locality),
    postal_code     = COALESCE(excluded.postal_code,     location.postal_code),
    street_name     = COALESCE(excluded.street_name,     location.street_name),
    building_number = COALESCE(excluded.building_number, location.building_number),
    updated_at      = CURRENT_TIMESTAMP`

// Param: :street_address
const selectEntityIDByLocationText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'location' LIMIT 1)
  AND natural_key = lower(:street_address)
LIMIT 1`

// Param: :row_id
const selectLocationByID = `
SELECT id, created_at, updated_at, city, unit, street_address, country, 
	   building, province, locality, postal_code, street_name, building_number 
FROM location 
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertLocation(ctx context.Context, a *contact.Location) (int64, error) {
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

	var c, u string
	var row_id int64
	var a contact.Location
	if err := result.Row.Scan(&row_id, &c, &u, &a.City, &a.Unit, &a.Address, &a.Country,
		&a.Building, &a.Province, &a.Locality, &a.PostalCode, &a.StreetName, &a.BuildingNumber); err != nil {
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
