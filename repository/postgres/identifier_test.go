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
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
)

func (suite *PostgresRepoTestSuite) TestCreateAssetForIdentifier() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	unique_id := "someone@owasp.org"
	idtype := oamgen.EmailAddress
	created := time.Now().Add(-24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	updated := time.Now().Add(-1 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	expiration := time.Now().Add(24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	status := "active"
	idasset, err := suite.db.CreateAsset(ctx, &oamgen.Identifier{
		UniqueID:       unique_id,
		Type:           idtype,
		CreationDate:   created,
		UpdatedDate:    updated,
		ExpirationDate: expiration,
		Status:         status,
	})
	assert.NoError(t, err, "Failed to create asset for the Identifier")
	assert.NotNil(t, idasset, "Entity for the Identifier should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, idasset.CreatedAt, before, after, "Identifier entity CreatedAt is incorrect")
	assert.WithinRange(t, idasset.LastSeen, before, after, "Identifier entity LastSeen is incorrect")

	id, err := strconv.ParseInt(idasset.ID, 10, 64)
	assert.NoError(t, err, "Identifier entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Identifier entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, idasset.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Identifier")
	assert.NotNil(t, found, "Entity found by ID for the Identifier should not be nil")
	assert.Equal(t, idasset.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Identifier does not match")
	assert.Equal(t, idasset.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Identifier does not match")

	idasset2, ok := found.Asset.(*oamgen.Identifier)
	assert.True(t, ok, "Asset found by ID is not of type *oamgen.Identifier")
	assert.Equal(t, found.ID, idasset.ID, "Identifier found by Entity ID does not have matching IDs")
	assert.Equal(t, idasset2.UniqueID, unique_id, "Identifier found by ID does not have a matching UniqueID")
	assert.Equal(t, idasset2.Type, idtype, "Identifier found by ID does not have a matching Type")
	assert.Equal(t, idasset2.CreationDate, created, "Identifier found by ID does not have a matching CreationDate")
	assert.Equal(t, idasset2.UpdatedDate, updated, "Identifier found by ID does not have a matching UpdatedDate")
	assert.Equal(t, idasset2.ExpirationDate, expiration, "Identifier found by ID does not have a matching ExpirationDate")
	assert.Equal(t, idasset2.Status, status, "Identifier found by ID does not have a matching Status")

	err = suite.db.DeleteEntity(ctx, idasset.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Identifier")

	_, err = suite.db.FindEntityById(ctx, idasset.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Identifier")
}

func (suite *PostgresRepoTestSuite) TestFindEntitiesByContentForIdentifier() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	unique_id := "someone@owasp.org"
	idtype := oamgen.EmailAddress
	created := time.Now().Add(-24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	updated := time.Now().Add(-1 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	expiration := time.Now().Add(24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	status := "active"
	idasset, err := suite.db.CreateAsset(ctx, &oamgen.Identifier{
		UniqueID:       unique_id,
		Type:           idtype,
		CreationDate:   created,
		UpdatedDate:    updated,
		ExpirationDate: expiration,
		Status:         status,
	})
	assert.NoError(t, err, "Failed to create asset for the Identifier")
	assert.NotNil(t, idasset, "Entity for the Identifier should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindOneEntityByContent(ctx, oam.Identifier, after, dbt.ContentFilters{
		"id": unique_id,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := suite.db.FindOneEntityByContent(ctx, oam.Identifier, before, dbt.ContentFilters{
		"id": unique_id,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Identifier")
	assert.NotNil(t, found, "Entity found by content for the Identifier should not be nil")

	idasset2, ok := found.Asset.(*oamgen.Identifier)
	assert.True(t, ok, "Identifier found by content is not of type *oamgen.Identifier")
	assert.Equal(t, found.ID, idasset.ID, "Identifier found by content does not have matching IDs")
	assert.Equal(t, idasset2.UniqueID, unique_id, "Identifier found by ID does not have a matching UniqueID")
	assert.Equal(t, idasset2.Type, idtype, "Identifier found by ID does not have a matching Type")
	assert.Equal(t, idasset2.CreationDate, created, "Identifier found by ID does not have a matching CreationDate")
	assert.Equal(t, idasset2.UpdatedDate, updated, "Identifier found by ID does not have a matching UpdatedDate")
	assert.Equal(t, idasset2.ExpirationDate, expiration, "Identifier found by ID does not have a matching ExpirationDate")
	assert.Equal(t, idasset2.Status, status, "Identifier found by ID does not have a matching Status")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.Identifier, before, dbt.ContentFilters{
		"id": unique_id,
	})
	assert.NoError(t, err, "Failed to find entities by content for the Identifier")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Identifier")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.Identifier, before, dbt.ContentFilters{
		"id_type": idtype,
	})
	assert.NoError(t, err, "Failed to find entities by content for the Identifier")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Identifier")
}
