// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"strconv"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForAutonomousSystem(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	number := 26808
	asn, err := db.CreateAsset(ctx, &oamnet.AutonomousSystem{Number: number})
	assert.NoError(t, err, "Failed to create asset for the AutonomousSystem")
	assert.NotNil(t, asn, "Entity for the AutonomousSystem should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, asn.CreatedAt, before, after, "AutonomousSystem entity CreatedAt is incorrect")
	assert.WithinRange(t, asn.LastSeen, before, after, "AutonomousSystem entity LastSeen is incorrect")

	id, err := strconv.ParseInt(asn.ID, 10, 64)
	assert.NoError(t, err, "AutonomousSystem entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "AutonomousSystem entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, asn.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the AutonomousSystem")
	assert.NotNil(t, found, "Entity found by ID for the AutonomousSystem should not be nil")
	assert.Equal(t, asn.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the AutonomousSystem does not match")
	assert.Equal(t, asn.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the AutonomousSystem does not match")

	asn2, ok := found.Asset.(*oamnet.AutonomousSystem)
	assert.True(t, ok, "Asset found by ID is not of type *oamnet.AutonomousSystem")
	assert.Equal(t, found.ID, asn.ID, "AutonomousSystem found by Entity ID does not have matching IDs")
	assert.Equal(t, asn2.Number, number, "AutonomousSystem found by ID does not have matching number")

	err = db.DeleteEntity(ctx, asn.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the AutonomousSystem")

	_, err = db.FindEntityById(ctx, asn.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the AutonomousSystem")
}

func TestFindEntitiesByContentForAutonomousSystem(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	number := 26808
	asn, err := db.CreateAsset(ctx, &oamnet.AutonomousSystem{Number: number})
	assert.NoError(t, err, "Failed to create asset for the AutonomousSystem")
	assert.NotNil(t, asn, "Entity for the AutonomousSystem should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = db.FindOneEntityByContent(ctx, oam.AutonomousSystem, after, dbt.ContentFilters{
		"number": number,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := db.FindOneEntityByContent(ctx, oam.AutonomousSystem, before, dbt.ContentFilters{
		"number": number,
	})
	assert.NoError(t, err, "Failed to find entity by content for the AutonomousSystem")
	assert.NotNil(t, found, "Entity found by content for the AutonomousSystem should not be nil")

	asn2, ok := found.Asset.(*oamnet.AutonomousSystem)
	assert.True(t, ok, "AutonomousSystem found by content is not of type *oamnet.AutonomousSystem")
	assert.Equal(t, found.ID, asn.ID, "AutonomousSystem found by content does not have matching IDs")
	assert.Equal(t, asn2.Number, number, "AutonomousSystem Number found by content does not match")

	ents, err := db.FindEntitiesByContent(ctx, oam.AutonomousSystem, before, dbt.ContentFilters{
		"number": number,
	})
	assert.NoError(t, err, "Failed to find entities by content for the AutonomousSystem")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the AutonomousSystem")
}
