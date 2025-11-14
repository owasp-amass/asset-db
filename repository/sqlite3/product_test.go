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
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForProduct(t *testing.T) {
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
	name := "Fake Product"
	ptype := "Fake Product Type"
	cat := "Fake Category"
	desc := "This is a fake product used for testing purposes."
	country := "US"

	product, err := db.CreateAsset(ctx, &oamplat.Product{
		ID:              uniqueID,
		Name:            name,
		Type:            ptype,
		Category:        cat,
		Description:     desc,
		CountryOfOrigin: country,
	})
	assert.NoError(t, err, "Failed to create asset for the Product")
	assert.NotNil(t, product, "Entity for the Product should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, product.CreatedAt, before, after, "Product entity CreatedAt is incorrect")
	assert.WithinRange(t, product.LastSeen, before, after, "Product entity LastSeen is incorrect")

	id, err := strconv.ParseInt(product.ID, 10, 64)
	assert.NoError(t, err, "Product entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Product entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, product.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Product")
	assert.NotNil(t, found, "Entity found by ID for the Product should not be nil")
	assert.Equal(t, product.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Product does not match")
	assert.Equal(t, product.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Product does not match")

	product2, ok := found.Asset.(*oamplat.Product)
	assert.True(t, ok, "Product found by ID is not of type *oamplat.Product")
	assert.Equal(t, found.ID, product.ID, "Product found by Entity ID does not have matching IDs")
	assert.Equal(t, product2.ID, uniqueID, "Product found by ID does not have matching UniqueID")
	assert.Equal(t, product2.Name, name, "Product found by ID does not have matching Name")
	assert.Equal(t, product2.Type, ptype, "Product found by ID does not have matching Type")
	assert.Equal(t, product2.Category, cat, "Product found by ID does not have matching Category")
	assert.Equal(t, product2.Description, desc, "Product found by ID does not have matching Description")
	assert.Equal(t, product2.CountryOfOrigin, country, "Product found by ID does not have matching CountryOfOrigin")

	err = db.DeleteEntity(ctx, product.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Product")

	_, err = db.FindEntityById(ctx, product.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Product")
}

func TestFindEntitiesByContentForProduct(t *testing.T) {
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
	name := "Fake Product"
	ptype := "Fake Product Type"
	cat := "Fake Category"
	desc := "This is a fake product used for testing purposes."
	country := "US"

	product, err := db.CreateAsset(ctx, &oamplat.Product{
		ID:              uniqueID,
		Name:            name,
		Type:            ptype,
		Category:        cat,
		Description:     desc,
		CountryOfOrigin: country,
	})
	assert.NoError(t, err, "Failed to create asset for the Product")
	assert.NotNil(t, product, "Entity for the Product should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = db.FindOneEntityByContent(ctx, oam.Product, after, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := db.FindOneEntityByContent(ctx, oam.Product, before, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Product")
	assert.NotNil(t, found, "Entity found by content for the Product should not be nil")

	product2, ok := found.Asset.(*oamplat.Product)
	assert.True(t, ok, "Product found by content is not of type *oamplat.Product")
	assert.Equal(t, found.ID, product.ID, "Product found by content does not have matching IDs")
	assert.Equal(t, product2.ID, uniqueID, "Product found by content does not have matching unique ID")
	assert.Equal(t, product2.Name, name, "Product found by content does not have matching name")
	assert.Equal(t, product2.Type, ptype, "Product found by content does not have matching type")
	assert.Equal(t, product2.Category, cat, "Product found by content does not have matching category")
	assert.Equal(t, product2.Description, desc, "Product found by content does not have matching description")
	assert.Equal(t, product2.CountryOfOrigin, country, "Product found by content does not have matching country of origin")

	for k, v := range map[string]string{
		"unique_id":    uniqueID,
		"product_name": name,
		"product_type": ptype,
	} {
		ents, err := db.FindEntitiesByContent(ctx, oam.Product, before, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the Product")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Product")
	}
}
