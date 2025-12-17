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
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForService(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uniqueID := "fake unique id"
	stype := "Fake Service Type"
	output := "This is a fake service used for testing purposes."
	outlen := len(output)
	attributes := map[string][]string{ // html headers
		"X-Fake-Header": {"FakeHeaderValue1", "FakeHeaderValue2"},
	}

	service, err := db.CreateAsset(ctx, &oamplat.Service{
		ID:         uniqueID,
		Type:       stype,
		Output:     output,
		OutputLen:  outlen,
		Attributes: attributes,
	})
	assert.NoError(t, err, "Failed to create asset for the Service")
	assert.NotNil(t, service, "Entity for the Service should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, service.CreatedAt, before, after, "Service entity CreatedAt is incorrect")
	assert.WithinRange(t, service.LastSeen, before, after, "Service entity LastSeen is incorrect")

	id, err := strconv.ParseInt(service.ID, 10, 64)
	assert.NoError(t, err, "Service entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Service entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, service.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Service")
	assert.NotNil(t, found, "Entity found by ID for the Service should not be nil")
	assert.Equal(t, service.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Service does not match")
	assert.Equal(t, service.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Service does not match")

	service2, ok := found.Asset.(*oamplat.Service)
	assert.True(t, ok, "Service found by ID is not of type *oamplat.Service")
	assert.Equal(t, found.ID, service.ID, "Service found by Entity ID does not have matching IDs")
	assert.Equal(t, service2.ID, uniqueID, "Service found by ID does not have matching UniqueID")
	assert.Equal(t, service2.Type, stype, "Service found by ID does not have matching Type")
	assert.Equal(t, service2.Output, output, "Service found by ID does not have matching Output")
	assert.Equal(t, service2.OutputLen, outlen, "Service found by ID does not have matching OutputLen")
	assert.Equal(t, service2.Attributes, attributes, "Service found by ID does not have matching Attributes")

	err = db.DeleteEntity(ctx, service.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Service")

	_, err = db.FindEntityById(ctx, service.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Service")
}

func TestFindEntitiesByContentForService(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uniqueID := "fake unique id"
	stype := "Fake Service Type"
	output := "This is a fake service used for testing purposes."
	outlen := len(output)
	attributes := map[string][]string{ // html headers
		"X-Fake-Header": {"FakeHeaderValue1", "FakeHeaderValue2"},
	}

	service, err := db.CreateAsset(ctx, &oamplat.Service{
		ID:         uniqueID,
		Type:       stype,
		Output:     output,
		OutputLen:  outlen,
		Attributes: attributes,
	})
	assert.NoError(t, err, "Failed to create asset for the Service")
	assert.NotNil(t, service, "Entity for the Service should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = db.FindOneEntityByContent(ctx, oam.Service, after, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := db.FindOneEntityByContent(ctx, oam.Service, before, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Service")
	assert.NotNil(t, found, "Entity found by content for the Service should not be nil")

	service2, ok := found.Asset.(*oamplat.Service)
	assert.True(t, ok, "Service found by content is not of type *oamplat.Service")
	assert.Equal(t, found.ID, service.ID, "Service found by content does not have matching IDs")
	assert.Equal(t, service2.ID, uniqueID, "Service found by content does not have matching unique ID")
	assert.Equal(t, service2.Type, stype, "Service found by content does not have matching type")
	assert.Equal(t, service2.Output, output, "Service found by content does not have matching output")
	assert.Equal(t, service2.OutputLen, outlen, "Service found by content does not have matching output length")
	assert.Equal(t, service2.Attributes, attributes, "Service found by content does not have matching attributes")

	for k, v := range map[string]string{
		"unique_id":    uniqueID,
		"service_type": stype,
	} {
		ents, err := db.FindEntitiesByContent(ctx, oam.Service, before, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the Service")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Service")
	}
}
