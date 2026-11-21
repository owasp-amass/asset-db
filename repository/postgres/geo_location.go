// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: @record::jsonb
const upsertGeoLocationText = `SELECT public.geolocation_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectGeoLocationByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.latitude, a.longitude, a.altitude,
a.uncertainty
FROM public.geolocation_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectGeoLocationFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.latitude, a.longitude,
a.altitude, a.uncertainty
FROM public.geolocation_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectGeoLocationSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.latitude, a.longitude,
a.altitude, a.uncertainty
FROM public.geolocation_updated_since(@since::timestamp, @limit::integer) AS a;`

// geoLocationRecord is the row written for a GeoLocation: the position is
// stored rounded to the six decimal places of its key, so the row matches its
// identity, and a zero altitude or uncertainty is stored as unknown.
type geoLocationRecord struct {
	UniqueID    string   `json:"unique_id"`
	Latitude    float64  `json:"latitude"`
	Longitude   float64  `json:"longitude"`
	Altitude    *float64 `json:"altitude,omitempty"`
	Uncertainty *float64 `json:"uncertainty,omitempty"`
}

func newGeoLocationRecord(a *contact.GeoLocation) geoLocationRecord {
	rec := geoLocationRecord{
		UniqueID:  a.Key(),
		Latitude:  roundMicrodegrees(a.Latitude),
		Longitude: roundMicrodegrees(a.Longitude),
	}
	if a.Altitude != 0 {
		alt := a.Altitude
		rec.Altitude = &alt
	}
	if a.Uncertainty > 0 {
		u := a.Uncertainty
		rec.Uncertainty = &u
	}
	return rec
}

// roundMicrodegrees rounds a coordinate to six decimal places, as the key does.
func roundMicrodegrees(v float64) float64 {
	r, err := strconv.ParseFloat(strconv.FormatFloat(v, 'f', 6, 64), 64)
	if err != nil || math.IsNaN(r) {
		return v
	}
	return r
}

func (r *PostgresRepository) upsertGeoLocation(ctx context.Context, a *contact.GeoLocation) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid geolocation provided")
	}
	if !a.Valid() {
		return 0, fmt.Errorf("the geolocation %s is not a point on the Earth", a.Key())
	}

	record, err := json.Marshal(newGeoLocationRecord(a))
	if err != nil {
		return 0, err
	}

	var id int64
	j := NewRowJob(ctx, upsertGeoLocationText, pgx.NamedArgs{
		"record": string(record),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.wpool.Submit(j)
	return id, j.Wait()
}

// geoLocationRow holds the columns read for one geolocation.
type geoLocationRow struct {
	eid, rid              int64
	created, updated      time.Time
	key                   string
	lat, lon              float64
	altitude, uncertainty pgtype.Float8
}

// dest returns the scan destinations after the entity ID, in column order.
func (g *geoLocationRow) dest() []any {
	return []any{&g.rid, &g.created, &g.updated, &g.key, &g.lat, &g.lon,
		&g.altitude, &g.uncertainty}
}

func (r *PostgresRepository) fetchGeoLocationByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	g := geoLocationRow{eid: eid}

	j := NewRowJob(ctx, selectGeoLocationByIDText, pgx.NamedArgs{
		"row_id": rowID,
	}, func(row pgx.Row) error {
		return row.Scan(g.dest()...)
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return buildGeoLocationEntity(&g)
}

func (r *PostgresRepository) findGeoLocationsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	lmt := zeronull.Int4(int32(limit))

	return r.scanGeoLocations(ctx, selectGeoLocationFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	})
}

func (r *PostgresRepository) getGeoLocationsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	return r.scanGeoLocations(ctx, selectGeoLocationSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	})
}

// scanGeoLocations runs a query whose rows are an entity ID followed by the
// columns of the GeoLocations updated-since query, and builds the entities.
func (r *PostgresRepository) scanGeoLocations(ctx context.Context, query string, args pgx.NamedArgs) ([]*dbt.Entity, error) {
	var out []*dbt.Entity
	j := NewRowsJob(ctx, query, args, func(rows pgx.Rows) error {
		for rows.Next() {
			var g geoLocationRow

			if err := rows.Scan(append([]any{&g.eid}, g.dest()...)...); err != nil {
				continue
			}
			if ent, err := buildGeoLocationEntity(&g); err == nil {
				out = append(out, ent)
			}
		}
		return rows.Err()
	})

	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

func buildGeoLocationEntity(g *geoLocationRow) (*dbt.Entity, error) {
	if g.rid == 0 {
		return nil, fmt.Errorf("no geolocation record found with row ID %d", g.rid)
	}
	if g.key == "" {
		return nil, fmt.Errorf("geolocation record with row ID %d is missing its unique ID", g.rid)
	}

	a := &contact.GeoLocation{
		Latitude:    g.lat,
		Longitude:   g.lon,
		Altitude:    g.altitude.Float64,
		Uncertainty: g.uncertainty.Float64,
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(g.eid, 10),
		CreatedAt: g.created.In(time.UTC).Local(),
		LastSeen:  g.updated.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
