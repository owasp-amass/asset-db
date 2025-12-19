// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"strconv"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	"github.com/stretchr/testify/assert"
)

func (suite *PostgresRepoTestSuite) TestCreateAssetForProductRelease() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	name := "Fake Product Release"
	releaseDate := time.Date(2023, time.March, 15, 0, 0, 0, 0, time.UTC).Format("2006-01-02")

	release, err := suite.db.CreateAsset(ctx, &oamplat.ProductRelease{
		Name:        name,
		ReleaseDate: releaseDate,
	})
	assert.NoError(t, err, "Failed to create asset for the ProductRelease")
	assert.NotNil(t, release, "Entity for the ProductRelease should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, release.CreatedAt, before, after, "ProductRelease entity CreatedAt is incorrect")
	assert.WithinRange(t, release.LastSeen, before, after, "ProductRelease entity LastSeen is incorrect")

	id, err := strconv.ParseInt(release.ID, 10, 64)
	assert.NoError(t, err, "ProductRelease entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "ProductRelease entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, release.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the ProductRelease")
	assert.NotNil(t, found, "Entity found by ID for the ProductRelease should not be nil")
	assert.Equal(t, release.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the ProductRelease does not match")
	assert.Equal(t, release.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the ProductRelease does not match")

	release2, ok := found.Asset.(*oamplat.ProductRelease)
	assert.True(t, ok, "ProductRelease found by ID is not of type *oamplat.ProductRelease")
	assert.Equal(t, found.ID, release.ID, "ProductRelease found by Entity ID does not have matching IDs")
	assert.Equal(t, release2.Name, name, "ProductRelease found by ID does not have matching Name")
	assert.Equal(t, release2.ReleaseDate, releaseDate, "ProductRelease found by ID does not have matching ReleaseDate")

	err = suite.db.DeleteEntity(ctx, release.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the ProductRelease")

	_, err = suite.db.FindEntityById(ctx, release.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the ProductRelease")
}

func (suite *PostgresRepoTestSuite) TestFindEntitiesByContentForProductRelease() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	name := "Fake Product Release"
	releaseDate := time.Date(2023, time.March, 15, 0, 0, 0, 0, time.UTC).Format("2006-01-02")

	release, err := suite.db.CreateAsset(ctx, &oamplat.ProductRelease{
		Name:        name,
		ReleaseDate: releaseDate,
	})
	assert.NoError(t, err, "Failed to create asset for the ProductRelease")
	assert.NotNil(t, release, "Entity for the ProductRelease should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindOneEntityByContent(ctx, oam.ProductRelease, after, dbt.ContentFilters{
		"name": name,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := suite.db.FindOneEntityByContent(ctx, oam.ProductRelease, before, dbt.ContentFilters{
		"name": name,
	})
	assert.NoError(t, err, "Failed to find entity by content for the ProductRelease")
	assert.NotNil(t, found, "Entity found by content for the ProductRelease should not be nil")

	release2, ok := found.Asset.(*oamplat.ProductRelease)
	assert.True(t, ok, "ProductRelease found by content is not of type *oamplat.ProductRelease")
	assert.Equal(t, found.ID, release.ID, "ProductRelease found by content does not have matching IDs")
	assert.Equal(t, release2.Name, name, "ProductRelease found by content does not have matching name")
	assert.Equal(t, release2.ReleaseDate, releaseDate, "ProductRelease found by content does not have matching release date")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.ProductRelease, before, dbt.ContentFilters{
		"name": name,
	})
	assert.NoError(t, err, "Failed to find entities by content for the ProductRelease")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the ProductRelease")
}
