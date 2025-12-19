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
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/stretchr/testify/assert"
)

func (suite *PostgresRepoTestSuite) TestCreateAssetForFQDN() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	name := "example.com"
	fasset, err := suite.db.CreateAsset(ctx, &oamdns.FQDN{
		Name: name,
	})
	assert.NoError(t, err, "Failed to create asset for the FQDN")
	assert.NotNil(t, fasset, "Entity for the FQDN should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, fasset.CreatedAt, before, after, "FQDN entity CreatedAt is incorrect")
	assert.WithinRange(t, fasset.LastSeen, before, after, "FQDN entity LastSeen is incorrect")

	id, err := strconv.ParseInt(fasset.ID, 10, 64)
	assert.NoError(t, err, "FQDN entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "FQDN entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, fasset.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the FQDN")
	assert.NotNil(t, found, "Entity found by ID for the FQDN should not be nil")
	assert.Equal(t, fasset.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the FQDN does not match")
	assert.Equal(t, fasset.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the FQDN does not match")

	fasset2, ok := found.Asset.(*oamdns.FQDN)
	assert.True(t, ok, "Asset found by ID is not of type *oamdns.FQDN")
	assert.Equal(t, found.ID, fasset.ID, "FQDN found by Entity ID does not have matching IDs")
	assert.Equal(t, fasset2.Name, name, "FQDN found by ID does not have a matching Name")

	err = suite.db.DeleteEntity(ctx, fasset.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the FQDN")

	_, err = suite.db.FindEntityById(ctx, fasset.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the FQDN")
}

func (suite *PostgresRepoTestSuite) TestFindEntitiesByContentForFQDN() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	name := "example.com"
	fasset, err := suite.db.CreateAsset(ctx, &oamdns.FQDN{
		Name: name,
	})
	assert.NoError(t, err, "Failed to create asset for the FQDN")
	assert.NotNil(t, fasset, "Entity for the FQDN should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindOneEntityByContent(ctx, oam.FQDN, after, dbt.ContentFilters{
		"name": name,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := suite.db.FindOneEntityByContent(ctx, oam.FQDN, before, dbt.ContentFilters{
		"name": name,
	})
	assert.NoError(t, err, "Failed to find entity by content for the FQDN")
	assert.NotNil(t, found, "Entity found by content for the FQDN should not be nil")

	fasset2, ok := found.Asset.(*oamdns.FQDN)
	assert.True(t, ok, "FQDN found by content is not of type *oamdns.FQDN")
	assert.Equal(t, found.ID, fasset.ID, "FQDN found by content does not have matching IDs")
	assert.Equal(t, fasset2.Name, name, "FQDN found by ID does not have a matching Name")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.FQDN, before, dbt.ContentFilters{
		"name": name,
	})
	assert.NoError(t, err, "Failed to find entities by content for the FQDN")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the FQDN")
}
