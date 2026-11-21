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
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorageBucketRoundTripAndLatestState(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err, "Failed to create the sqlite database")
	defer teardownTempSQLite(db, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now().Add(-time.Second)
	public := &oamplat.StorageBucket{
		ID:       "s3:example-public",
		Name:     "example-public",
		Provider: "Amazon Web Services",
		Service:  "s3",
		Exists:   true,
		Public:   true,
	}
	ent, err := db.CreateAsset(ctx, public)
	require.NoError(t, err, "Failed to create asset for the StorageBucket")

	found, err := db.FindEntityById(ctx, ent.ID)
	require.NoError(t, err, "Failed to find the StorageBucket by ID")
	got, ok := found.Asset.(*oamplat.StorageBucket)
	require.True(t, ok, "the asset is not a *oamplat.StorageBucket")
	assert.Equal(t, *public, *got, "the StorageBucket did not round-trip")

	// the bucket is deleted at the provider: a later sighting without the
	// provider replaces the state but keeps the known provider
	absent, err := db.CreateAsset(ctx, &oamplat.StorageBucket{
		ID:   "s3:example-public",
		Name: "example-public",
	})
	require.NoError(t, err, "Failed to update the StorageBucket")
	assert.Equal(t, ent.ID, absent.ID, "the same bucket is the same entity")

	got = absent.Asset.(*oamplat.StorageBucket)
	assert.False(t, got.Exists, "the latest sighting says the bucket is absent")
	assert.False(t, got.Public, "an absent bucket is not public")
	assert.Equal(t, "Amazon Web Services", got.Provider, "the known provider is kept")
	assert.Equal(t, "s3", got.Service, "the known service is kept")

	ents, err := db.FindEntitiesByContent(ctx, oam.StorageBucket, before, 0, dbt.ContentFilters{
		"exists": false,
	})
	require.NoError(t, err, "Failed to find absent StorageBuckets by content")
	require.Len(t, ents, 1, "the absent bucket is found by its state")
	assert.Equal(t, ent.ID, ents[0].ID)

	ents, err = db.FindEntitiesByType(ctx, oam.StorageBucket, before, 0)
	require.NoError(t, err, "Failed to find StorageBuckets by type")
	assert.Len(t, ents, 1)

	require.NoError(t, db.DeleteEntity(ctx, ent.ID), "Failed to delete the StorageBucket")
	_, err = db.FindEntityById(ctx, ent.ID)
	assert.Error(t, err, "a deleted StorageBucket is not found")
}
