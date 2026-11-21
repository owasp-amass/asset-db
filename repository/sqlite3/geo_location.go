// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	_ "modernc.org/sqlite"
)

// Params: :unique_id, :latitude, :longitude, :altitude, :uncertainty
//
// Altitude takes the latest known value; uncertainty keeps the smallest
// radius observed, since the best sighting of a point is the one to trust.
const upsertGeoLocationText = `
INSERT INTO geolocation(unique_id, latitude, longitude, altitude, uncertainty)
VALUES (:unique_id, :latitude, :longitude, :altitude, :uncertainty)
ON CONFLICT(unique_id) DO UPDATE SET
    altitude    = COALESCE(excluded.altitude, geolocation.altitude),
    uncertainty = CASE
        WHEN excluded.uncertainty IS NULL THEN geolocation.uncertainty
        WHEN geolocation.uncertainty IS NULL THEN excluded.uncertainty
        ELSE MIN(excluded.uncertainty, geolocation.uncertainty)
    END,
    updated_at  = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByGeoLocationText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'geolocation' LIMIT 1)
  AND natural_key = :unique_id
LIMIT 1`

// Param: :row_id
const selectGeoLocationByIDText = `
SELECT id, created_at, updated_at, unique_id, latitude, longitude, altitude, uncertainty
FROM geolocation
WHERE id = :row_id
LIMIT 1`

// roundMicrodegrees rounds a coordinate to six decimal places, as the key
// does, so the row matches its identity.
func roundMicrodegrees(v float64) float64 {
	r, err := strconv.ParseFloat(strconv.FormatFloat(v, 'f', 6, 64), 64)
	if err != nil {
		return v
	}
	return r
}

// zeroToNil stores an unknown (zero) measurement as NULL, so the upsert keeps
// a value already known.
func zeroToNil(v float64) any {
	if v == 0 {
		return nil
	}
	return v
}

func (r *SqliteRepository) upsertGeoLocation(ctx context.Context, a *contact.GeoLocation) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid geolocation provided")
	}
	if !a.Valid() {
		return 0, fmt.Errorf("the geolocation %s is not a point on the Earth", a.Key())
	}

	uncertainty := a.Uncertainty
	if uncertainty < 0 {
		uncertainty = 0
	}

	key := a.Key()
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.geolocation.upsert",
		SQLText: upsertGeoLocationText,
		Args: []any{
			sql.Named("unique_id", key),
			sql.Named("latitude", roundMicrodegrees(a.Latitude)),
			sql.Named("longitude", roundMicrodegrees(a.Longitude)),
			sql.Named("altitude", zeroToNil(a.Altitude)),
			sql.Named("uncertainty", zeroToNil(uncertainty)),
		},
		Result: done,
	})
	if err := <-done; err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.geolocation.entity_id_by_unique_id",
		SQLText: selectEntityIDByGeoLocationText,
		Args:    []any{sql.Named("unique_id", key)},
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

func (r *SqliteRepository) fetchGeoLocationByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.geolocation.by_id",
		SQLText: selectGeoLocationByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var c, u, key string
	var altitude, uncertainty sql.NullFloat64
	var a contact.GeoLocation
	if err := result.Row.Scan(&row_id, &c, &u, &key, &a.Latitude, &a.Longitude,
		&altitude, &uncertainty); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, fmt.Errorf("no geolocation record found with row ID %d", rowID)
	}
	if key == "" {
		return nil, fmt.Errorf("geolocation record with row ID %d is missing its unique ID", rowID)
	}
	a.Altitude = altitude.Float64
	a.Uncertainty = uncertainty.Float64

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
