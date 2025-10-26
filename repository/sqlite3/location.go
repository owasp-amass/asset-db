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

// LOCATION -------------------------------------------------------------------
// Params: :city, :street_address, :country, :unit, :building, :province, :locality, :postal_code, :street_name, :building_number, :attrs
const tmplUpsertLocation = `
WITH
  row_try AS (
    INSERT INTO location(city, street_address, country, unit, building, province, locality, postal_code, street_name, building_number)
    VALUES (:city, :street_address, :country, :unit, :building, :province, :locality, :postal_code, :street_name, :building_number)
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
      updated_at      = CASE WHEN
        (excluded.city            IS NOT location.city) OR
        (excluded.country         IS NOT location.country) OR
        (excluded.unit            IS NOT location.unit) OR
        (excluded.building        IS NOT location.building) OR
        (excluded.province        IS NOT location.province) OR
        (excluded.locality        IS NOT location.locality) OR
        (excluded.postal_code     IS NOT location.postal_code) OR
        (excluded.street_name     IS NOT location.street_name) OR
        (excluded.building_number IS NOT location.building_number)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE location.updated_at END
    WHERE (excluded.city            IS NOT location.city) OR
          (excluded.country         IS NOT location.country) OR
          (excluded.unit            IS NOT location.unit) OR
          (excluded.building        IS NOT location.building) OR
          (excluded.province        IS NOT location.province) OR
          (excluded.locality        IS NOT location.locality) OR
          (excluded.postal_code     IS NOT location.postal_code) OR
          (excluded.street_name     IS NOT location.street_name) OR
          (excluded.building_number IS NOT location.building_number)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM location WHERE street_address=:street_address LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('location') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='location' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :street_address, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:street_address LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'location',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

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

func (s *Statements) UpsertLocation(ctx context.Context, a *contact.Location) (int64, error) {
	row := s.UpsertLocationStmt.QueryRowContext(ctx,
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
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchLocationByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, city, unit, street_address, country, 
			  building, province, locality, postal_code, street_name, building_number
		      FROM location WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "location", query)
	if err != nil {
		return nil, err
	}

	var a Location
	var c, u *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.City, &a.Unit, &a.StreetAddress, &a.Country, &a.Building, &a.Province,
		&a.Locality, &a.PostalCode, &a.StreetName, &a.BuildingNumber,
	); err != nil {
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
		CreatedAt: (*a.CreatedAt).In(time.UTC).Local(),
		LastSeen:  (*a.UpdatedAt).In(time.UTC).Local(),
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
