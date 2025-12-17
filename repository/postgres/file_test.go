// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"strconv"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForFile(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	url := "https://www.owasp.org/contact.html"
	name := "contact.html"
	fileType := "text/html"
	fasset, err := db.CreateAsset(ctx, &oamfile.File{
		URL:  url,
		Name: name,
		Type: fileType,
	})
	assert.NoError(t, err, "Failed to create asset for the File")
	assert.NotNil(t, fasset, "Entity for the File should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, fasset.CreatedAt, before, after, "File entity CreatedAt is incorrect")
	assert.WithinRange(t, fasset.LastSeen, before, after, "File entity LastSeen is incorrect")

	id, err := strconv.ParseInt(fasset.ID, 10, 64)
	assert.NoError(t, err, "File entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "File entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, fasset.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the File")
	assert.NotNil(t, found, "Entity found by ID for the File should not be nil")
	assert.Equal(t, fasset.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the File does not match")
	assert.Equal(t, fasset.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the File does not match")

	fasset2, ok := found.Asset.(*oamfile.File)
	assert.True(t, ok, "Asset found by ID is not of type *oamfile.File")
	assert.Equal(t, found.ID, fasset.ID, "File found by Entity ID does not have matching IDs")
	assert.Equal(t, fasset2.URL, url, "File found by ID does not have a matching URL")
	assert.Equal(t, fasset2.Name, name, "File found by ID does not have a matching Name")
	assert.Equal(t, fasset2.Type, fileType, "File found by ID does not have a matching Type")

	err = db.DeleteEntity(ctx, fasset.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the File")

	_, err = db.FindEntityById(ctx, fasset.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the File")
}

func TestFindEntitiesByContentForFile(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	url := "https://www.owasp.org/contact.html"
	name := "contact.html"
	fileType := "text/html"
	fasset, err := db.CreateAsset(ctx, &oamfile.File{
		URL:  url,
		Name: name,
		Type: fileType,
	})
	assert.NoError(t, err, "Failed to create asset for the File")
	assert.NotNil(t, fasset, "Entity for the File should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = db.FindOneEntityByContent(ctx, oam.File, after, dbt.ContentFilters{
		"url": url,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := db.FindOneEntityByContent(ctx, oam.File, before, dbt.ContentFilters{
		"url": url,
	})
	assert.NoError(t, err, "Failed to find entity by content for the File")
	assert.NotNil(t, found, "Entity found by content for the File should not be nil")

	fasset2, ok := found.Asset.(*oamfile.File)
	assert.True(t, ok, "File found by content is not of type *oamfile.File")
	assert.Equal(t, found.ID, fasset.ID, "File found by content does not have matching IDs")
	assert.Equal(t, fasset2.URL, url, "File found by ID does not have a matching URL")
	assert.Equal(t, fasset2.Name, name, "File found by ID does not have a matching Name")
	assert.Equal(t, fasset2.Type, fileType, "File found by ID does not have a matching Type")

	ents, err := db.FindEntitiesByContent(ctx, oam.File, before, dbt.ContentFilters{
		"name": name,
	})
	assert.NoError(t, err, "Failed to find entities by content for the File")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the File")

	ents, err = db.FindEntitiesByContent(ctx, oam.File, before, dbt.ContentFilters{
		"type": fileType,
	})
	assert.NoError(t, err, "Failed to find entities by content for the File")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the File")
}
