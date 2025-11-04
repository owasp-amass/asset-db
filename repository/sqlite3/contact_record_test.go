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
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForContactRecord(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	discovered := "Probably some URL"
	cr, err := db.CreateAsset(ctx, &oamcon.ContactRecord{DiscoveredAt: discovered})
	assert.NoError(t, err, "Failed to create asset for the ContactRecord")
	assert.NotNil(t, cr, "Entity for the ContactRecord should not be nil")
	after := time.Now()
	assert.WithinRange(t, cr.CreatedAt, before, after, "ContactRecord entity CreatedAt is incorrect")
	assert.WithinRange(t, cr.LastSeen, before, after, "ContactRecord entity LastSeen is incorrect")

	id, err := strconv.ParseInt(cr.ID, 10, 64)
	assert.NoError(t, err, "ContactRecord entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "ContactRecord entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, cr.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the ContactRecord")
	assert.NotNil(t, found, "Entity found by ID for the ContactRecord should not be nil")
	assert.Equal(t, cr.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the ContactRecord does not match")
	assert.Equal(t, cr.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the ContactRecord does not match")

	cr2, ok := found.Asset.(*oamcon.ContactRecord)
	assert.True(t, ok, "Asset found by ID is not of type *oamcon.ContactRecord")
	assert.Equal(t, found.ID, cr.ID, "ContactRecord found by Entity ID does not have matching IDs")
	assert.Equal(t, cr2.DiscoveredAt, discovered, "ContactRecord found by ID does not have matching DiscoveredAt")

	err = db.DeleteEntity(ctx, cr.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the ContactRecord")

	_, err = db.FindEntityById(ctx, cr.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the ContactRecord")
}

func TestFindEntitiesByContentForContactRecord(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	discovered := "Probably some URL"
	cr, err := db.CreateAsset(ctx, &oamcon.ContactRecord{DiscoveredAt: discovered})
	assert.NoError(t, err, "Failed to create asset for the ContactRecord")
	assert.NotNil(t, cr, "Entity for the ContactRecord should not be nil")
	after := time.Now()

	_, err = db.FindOneEntityByContent(ctx, string(oam.ContactRecord), after, dbt.ContentFilters{
		"discovered_at": discovered,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := db.FindOneEntityByContent(ctx, string(oam.ContactRecord), before, dbt.ContentFilters{
		"discovered_at": discovered,
	})
	assert.NoError(t, err, "Failed to find entity by content for the ContactRecord")
	assert.NotNil(t, found, "Entity found by content for the ContactRecord should not be nil")

	cr2, ok := found.Asset.(*oamcon.ContactRecord)
	assert.True(t, ok, "ContactRecord found by content is not of type *oamcon.ContactRecord")
	assert.Equal(t, found.ID, cr.ID, "ContactRecord found by content does not have matching IDs")
	assert.Equal(t, cr2.DiscoveredAt, discovered, "ContactRecord DiscoveredAt found by content does not match")

	ents, err := db.FindEntitiesByContent(ctx, string(oam.ContactRecord), before, dbt.ContentFilters{
		"discovered_at": discovered,
	})
	assert.NoError(t, err, "Failed to find entities by content for the ContactRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the ContactRecord")
}
