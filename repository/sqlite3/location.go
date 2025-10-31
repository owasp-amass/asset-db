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
  AND display_value = lower(:street_address)
LIMIT 1`

// Param: :row_id
const selectLocationByID = `
SELECT id, created_at, updated_at, city, unit, street_address, country, 
	   building, province, locality, postal_code, street_name, building_number 
FROM location 
WHERE id = :row_id
LIMIT 1`

type Location struct {
	ID             int64      `json:"id"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	City           string     `json:"city"`
	Unit           *string    `json:"unit,omitempty"`
	StreetAddress  string     `json:"street_address"`
	Country        string     `json:"country"`
	Building       *string    `json:"building,omitempty"`
	Province       *string    `json:"province,omitempty"`
	Locality       *string    `json:"locality,omitempty"`
	PostalCode     *string    `json:"postal_code,omitempty"`
	StreetName     *string    `json:"street_name,omitempty"`
	BuildingNumber *string    `json:"building_number,omitempty"`
}

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

	var a Location
	var c, u *string
	if err := result.Row.Scan(&a.ID, &c, &u, &a.City, &a.Unit, &a.StreetAddress, &a.Country,
		&a.Building, &a.Province, &a.Locality, &a.PostalCode, &a.StreetName, &a.BuildingNumber); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	if a.CreatedAt == nil || a.UpdatedAt == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var building string
	if a.Building != nil {
		building = *a.Building
	}

	var buildnum string
	if a.BuildingNumber != nil {
		buildnum = *a.BuildingNumber
	}

	var streetname string
	if a.StreetName != nil {
		streetname = *a.StreetName
	}

	var unit string
	if a.Unit != nil {
		unit = *a.Unit
	}

	var locality string
	if a.Locality != nil {
		locality = *a.Locality
	}

	var province string
	if a.Province != nil {
		province = *a.Province
	}

	var postalcode string
	if a.PostalCode != nil {
		postalcode = *a.PostalCode
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: a.CreatedAt.In(time.UTC).Local(),
		LastSeen:  a.UpdatedAt.In(time.UTC).Local(),
		Asset: &contact.Location{
			Address:        a.StreetAddress,
			Building:       building,
			BuildingNumber: buildnum,
			StreetName:     streetname,
			Unit:           unit,
			City:           a.City,
			Locality:       locality,
			Province:       province,
			Country:        a.Country,
			PostalCode:     postalcode,
		},
	}, nil
}
