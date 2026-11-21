// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeoLocationRoundTripAndBestUncertainty(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err, "Failed to create the sqlite database")
	defer teardownTempSQLite(db, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now().Add(-time.Second)
	// an IP geolocation good to a city
	city := &contact.GeoLocation{Latitude: 43.1009, Longitude: -75.2327, Uncertainty: 5000}
	ent, err := db.CreateAsset(ctx, city)
	require.NoError(t, err, "Failed to create asset for the GeoLocation")

	found, err := db.FindEntityById(ctx, ent.ID)
	require.NoError(t, err, "Failed to find the GeoLocation by ID")
	got, ok := found.Asset.(*contact.GeoLocation)
	require.True(t, ok, "the asset is not a *contact.GeoLocation")
	assert.Equal(t, *city, *got, "the GeoLocation did not round-trip")

	// a photo's GPS at the same point, beyond the sixth decimal place
	photo, err := db.CreateAsset(ctx, &contact.GeoLocation{
		Latitude: 43.10090004, Longitude: -75.23270004, Altitude: 150, Uncertainty: 8,
	})
	require.NoError(t, err, "Failed to update the GeoLocation")
	assert.Equal(t, ent.ID, photo.ID, "the same point is the same entity")
	got = photo.Asset.(*contact.GeoLocation)
	assert.Equal(t, 8.0, got.Uncertainty, "the smallest radius observed is kept")
	assert.Equal(t, 150.0, got.Altitude)

	// a later, coarser sighting does not widen the radius or lose the altitude
	again, err := db.CreateAsset(ctx, city)
	require.NoError(t, err)
	got = again.Asset.(*contact.GeoLocation)
	assert.Equal(t, 8.0, got.Uncertainty)
	assert.Equal(t, 150.0, got.Altitude)

	ents, err := db.FindEntitiesByContent(ctx, oam.GeoLocation, before, 0, dbt.ContentFilters{
		"unique_id": city.Key(),
	})
	require.NoError(t, err, "Failed to find the GeoLocation by content")
	require.Len(t, ents, 1)
	assert.Equal(t, ent.ID, ents[0].ID)

	ents, err = db.FindEntitiesByType(ctx, oam.GeoLocation, before, 0)
	require.NoError(t, err, "Failed to find GeoLocations by type")
	assert.Len(t, ents, 1)

	_, err = db.CreateAsset(ctx, &contact.GeoLocation{Latitude: 0, Longitude: 181})
	assert.Error(t, err, "a point off the Earth is refused")

	require.NoError(t, db.DeleteEntity(ctx, ent.ID), "Failed to delete the GeoLocation")
	_, err = db.FindEntityById(ctx, ent.ID)
	assert.Error(t, err, "a deleted GeoLocation is not found")
}
