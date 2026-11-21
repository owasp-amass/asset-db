// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	_ "modernc.org/sqlite"
)

// Params: :city, :street_address, :country, :unit, :building,
// :province, :locality, :postal_code, :street_name, :building_number, :attrs
const upsertStreetAddressText = `
INSERT INTO streetaddress(city, street_address, country, unit, building, province, locality, postal_code, street_name, building_number, attrs)
VALUES (:city, :street_address, :country, :unit, :building, :province, :locality, :postal_code, :street_name, :building_number, :attrs)
ON CONFLICT(street_address_norm) DO UPDATE SET
    city            = COALESCE(excluded.city,            streetaddress.city),
    country         = COALESCE(excluded.country,         streetaddress.country),
    unit            = COALESCE(excluded.unit,            streetaddress.unit),
    building        = COALESCE(excluded.building,        streetaddress.building),
    province        = COALESCE(excluded.province,        streetaddress.province),
    locality        = COALESCE(excluded.locality,        streetaddress.locality),
    postal_code     = COALESCE(excluded.postal_code,     streetaddress.postal_code),
    street_name     = COALESCE(excluded.street_name,     streetaddress.street_name),
    building_number = COALESCE(excluded.building_number, streetaddress.building_number),
    attrs           = json_patch(streetaddress.attrs,    excluded.attrs),
    updated_at      = CURRENT_TIMESTAMP`

// Param: :street_address
const selectEntityIDByStreetAddressText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'streetaddress' LIMIT 1)
  AND natural_key = lower(:street_address)
LIMIT 1`

// Param: :row_id
const selectStreetAddressByID = `
SELECT id, created_at, updated_at, city, unit, street_address, country, 
	   building, province, locality, postal_code, street_name, building_number, attrs
FROM streetaddress 
WHERE id = :row_id
LIMIT 1`

type streetAddressAttributes struct {
	POBox string `json:"po_box,omitempty"`
	GLN   int    `json:"gln,omitempty"`
}

func (r *SqliteRepository) upsertStreetAddress(ctx context.Context, a *contact.StreetAddress) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid street address provided")
	}
	if a.Address == "" {
		return 0, errors.New("the street address cannot be empty")
	}
	if a.City == "" {
		return 0, errors.New("street address city cannot be empty")
	}

	attrs := streetAddressAttributes{
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
		Name:    "asset.streetaddress.upsert",
		SQLText: upsertStreetAddressText,
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
		Name:    "asset.streetaddress.entity_id_by_streetaddress",
		SQLText: selectEntityIDByStreetAddressText,
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

func (r *SqliteRepository) fetchStreetAddressByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.streetaddress.by_id",
		SQLText: selectStreetAddressByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a contact.StreetAddress
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.City, &a.Unit,
		&a.Address, &a.Country, &a.Building, &a.Province, &a.Locality,
		&a.PostalCode, &a.StreetName, &a.BuildingNumber, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no street address found")
	}
	if a.Address == "" {
		return nil, errors.New("the street address is missing")
	}
	if a.City == "" {
		return nil, errors.New("street address city is missing")
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

	var attrs streetAddressAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.POBox = attrs.POBox
	a.GLN = attrs.GLN

	return e, nil
}
