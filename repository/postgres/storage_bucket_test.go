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
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PostgresStorageBucketTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresStorageBucketTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresStorageBucketTestSuite))
}

func (suite *PostgresStorageBucketTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresStorageBucketTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresStorageBucketTestSuite) TestRoundTripAndLatestState() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now().Add(-time.Second)
	public := &oamplat.StorageBucket{
		ID:       "gcs:example-public",
		Name:     "example-public",
		Provider: "Google Cloud",
		Service:  "gcs",
		Exists:   true,
		Public:   true,
	}
	ent, err := suite.db.CreateAsset(ctx, public)
	require.NoError(t, err, "Failed to create asset for the StorageBucket")

	found, err := suite.db.FindEntityById(ctx, ent.ID)
	require.NoError(t, err, "Failed to find the StorageBucket by ID")
	got, ok := found.Asset.(*oamplat.StorageBucket)
	require.True(t, ok, "the asset is not a *oamplat.StorageBucket")
	assert.Equal(t, *public, *got, "the StorageBucket did not round-trip")

	byIds, err := suite.db.FindEntitiesByIds(ctx, []string{ent.ID})
	require.NoError(t, err, "Failed to read the StorageBucket by IDs")
	require.Len(t, byIds, 1)
	assert.Equal(t, *public, *byIds[0].Asset.(*oamplat.StorageBucket))

	// the bucket is deleted at the provider: a later sighting without the
	// provider replaces the state but keeps the known provider
	absent, err := suite.db.CreateAsset(ctx, &oamplat.StorageBucket{
		ID:   "gcs:example-public",
		Name: "example-public",
	})
	require.NoError(t, err, "Failed to update the StorageBucket")
	assert.Equal(t, ent.ID, absent.ID, "the same bucket is the same entity")

	got = absent.Asset.(*oamplat.StorageBucket)
	assert.False(t, got.Exists, "the latest sighting says the bucket is absent")
	assert.False(t, got.Public, "an absent bucket is not public")
	assert.Equal(t, "Google Cloud", got.Provider, "the known provider is kept")
	assert.Equal(t, "gcs", got.Service, "the known service is kept")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.StorageBucket, before, 0, dbt.ContentFilters{
		"exists": false,
	})
	require.NoError(t, err, "Failed to find absent StorageBuckets by content")
	require.Len(t, ents, 1, "the absent bucket is found by its state")
	assert.Equal(t, ent.ID, ents[0].ID)

	ents, err = suite.db.FindEntitiesByType(ctx, oam.StorageBucket, before, 0)
	require.NoError(t, err, "Failed to find StorageBuckets by type")
	assert.Len(t, ents, 1)

	require.NoError(t, suite.db.DeleteEntity(ctx, ent.ID), "Failed to delete the StorageBucket")
	_, err = suite.db.FindEntityById(ctx, ent.ID)
	assert.Error(t, err, "a deleted StorageBucket is not found")
}
