// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/repository/postgres/testhelpers"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PostgresGeoLocationTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresGeoLocationTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresGeoLocationTestSuite))
}

func (suite *PostgresGeoLocationTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresGeoLocationTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresGeoLocationTestSuite) TestRoundTripAndBestUncertainty() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now().Add(-time.Second)
	// an IP geolocation good to a city
	city := &contact.GeoLocation{Latitude: 42.4534, Longitude: -75.0638, Uncertainty: 5000}
	ent, err := suite.db.CreateAsset(ctx, city)
	require.NoError(t, err, "Failed to create asset for the GeoLocation")

	found, err := suite.db.FindEntityById(ctx, ent.ID)
	require.NoError(t, err, "Failed to find the GeoLocation by ID")
	got, ok := found.Asset.(*contact.GeoLocation)
	require.True(t, ok, "the asset is not a *contact.GeoLocation")
	assert.Equal(t, *city, *got, "the GeoLocation did not round-trip")

	byIds, err := suite.db.FindEntitiesByIds(ctx, []string{ent.ID})
	require.NoError(t, err, "Failed to read the GeoLocation by IDs")
	require.Len(t, byIds, 1)
	assert.Equal(t, *city, *byIds[0].Asset.(*contact.GeoLocation))

	// a photo's GPS at the same point, beyond the sixth decimal place
	photo, err := suite.db.CreateAsset(ctx, &contact.GeoLocation{
		Latitude: 42.45340004, Longitude: -75.06380004, Altitude: 340, Uncertainty: 8,
	})
	require.NoError(t, err, "Failed to update the GeoLocation")
	assert.Equal(t, ent.ID, photo.ID, "the same point is the same entity")
	got = photo.Asset.(*contact.GeoLocation)
	assert.Equal(t, 8.0, got.Uncertainty, "the smallest radius observed is kept")
	assert.Equal(t, 340.0, got.Altitude)

	// a later, coarser sighting does not widen the radius or lose the altitude
	again, err := suite.db.CreateAsset(ctx, city)
	require.NoError(t, err)
	got = again.Asset.(*contact.GeoLocation)
	assert.Equal(t, 8.0, got.Uncertainty)
	assert.Equal(t, 340.0, got.Altitude)

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.GeoLocation, before, 0, dbt.ContentFilters{
		"unique_id": city.Key(),
	})
	require.NoError(t, err, "Failed to find the GeoLocation by content")
	require.Len(t, ents, 1)
	assert.Equal(t, ent.ID, ents[0].ID)

	ents, err = suite.db.FindEntitiesByType(ctx, oam.GeoLocation, before, 0)
	require.NoError(t, err, "Failed to find GeoLocations by type")
	assert.Len(t, ents, 1)

	_, err = suite.db.CreateAsset(ctx, &contact.GeoLocation{Latitude: 91, Longitude: 0})
	assert.Error(t, err, "a point off the Earth is refused")

	require.NoError(t, suite.db.DeleteEntity(ctx, ent.ID), "Failed to delete the GeoLocation")
	_, err = suite.db.FindEntityById(ctx, ent.ID)
	assert.Error(t, err, "a deleted GeoLocation is not found")
}
