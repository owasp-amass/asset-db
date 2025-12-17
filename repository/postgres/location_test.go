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
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForLocation(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	address := "123 Main Street, Apt 4B, Anytown, CA 91911 US"
	building := ""
	buildingNum := "123"
	streetName := "Main Street"
	unit := "Apt 4B"
	poBox := ""
	city := "Anytown"
	locality := "Some County"
	province := "CA"
	country := "US"
	postalCode := "91911"
	gln := 00012345600012

	loc, err := db.CreateAsset(ctx, &oamcon.Location{
		Address:        address,
		Building:       building,
		BuildingNumber: buildingNum,
		StreetName:     streetName,
		Unit:           unit,
		POBox:          poBox,
		City:           city,
		Locality:       locality,
		Province:       province,
		Country:        country,
		PostalCode:     postalCode,
		GLN:            gln,
	})
	assert.NoError(t, err, "Failed to create asset for the Location")
	assert.NotNil(t, loc, "Entity for the Location should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, loc.CreatedAt, before, after, "Location entity CreatedAt is incorrect")
	assert.WithinRange(t, loc.LastSeen, before, after, "Location entity LastSeen is incorrect")

	id, err := strconv.ParseInt(loc.ID, 10, 64)
	assert.NoError(t, err, "Location entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Location entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, loc.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Location")
	assert.NotNil(t, found, "Entity found by ID for the Location should not be nil")
	assert.Equal(t, loc.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Location does not match")
	assert.Equal(t, loc.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Location does not match")

	loc2, ok := found.Asset.(*oamcon.Location)
	assert.True(t, ok, "Location found by ID is not of type *oamcon.Location")
	assert.Equal(t, found.ID, loc.ID, "Location found by Entity ID does not have matching IDs")
	assert.Equal(t, loc2.Address, address, "Location found by ID does not have matching address")
	assert.Equal(t, loc2.Building, building, "Location found by ID does not have matching building")
	assert.Equal(t, loc2.BuildingNumber, buildingNum, "Location found by ID does not have matching building number")
	assert.Equal(t, loc2.StreetName, streetName, "Location found by ID does not have matching street name")
	assert.Equal(t, loc2.Unit, unit, "Location found by ID does not have matching unit")
	assert.Equal(t, loc2.POBox, poBox, "Location found by ID does not have matching PO Box")
	assert.Equal(t, loc2.City, city, "Location found by ID does not have matching city")
	assert.Equal(t, loc2.Locality, locality, "Location found by ID does not have matching locality")
	assert.Equal(t, loc2.Province, province, "Location found by ID does not have matching province")
	assert.Equal(t, loc2.Country, country, "Location found by ID does not have matching country")
	assert.Equal(t, loc2.PostalCode, postalCode, "Location found by ID does not have matching postal code")
	assert.Equal(t, loc2.GLN, gln, "Location found by ID does not have matching GLN")

	err = db.DeleteEntity(ctx, loc.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Location")

	_, err = db.FindEntityById(ctx, loc.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Location")
}

func TestFindEntitiesByContentForLocation(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	address := "123 Main Street, Apt 4B, Anytown, CA 91911 US"
	building := ""
	buildingNum := "123"
	streetName := "Main Street"
	unit := "Apt 4B"
	poBox := ""
	city := "Anytown"
	locality := "Some County"
	province := "CA"
	country := "US"
	postalCode := "91911"
	gln := 00012345600012

	loc, err := db.CreateAsset(ctx, &oamcon.Location{
		Address:        address,
		Building:       building,
		BuildingNumber: buildingNum,
		StreetName:     streetName,
		Unit:           unit,
		POBox:          poBox,
		City:           city,
		Locality:       locality,
		Province:       province,
		Country:        country,
		PostalCode:     postalCode,
		GLN:            gln,
	})
	assert.NoError(t, err, "Failed to create asset for the Location")
	assert.NotNil(t, loc, "Entity for the Location should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = db.FindOneEntityByContent(ctx, oam.Location, after, dbt.ContentFilters{
		"address": address,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := db.FindOneEntityByContent(ctx, oam.Location, before, dbt.ContentFilters{
		"address": address,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Location")
	assert.NotNil(t, found, "Entity found by content for the Location should not be nil")

	loc2, ok := found.Asset.(*oamcon.Location)
	assert.True(t, ok, "Location found by content is not of type *oamcon.Location")
	assert.Equal(t, found.ID, loc.ID, "Location found by content does not have matching IDs")
	assert.Equal(t, loc2.Address, address, "Location found by content does not have matching address")
	assert.Equal(t, loc2.Building, building, "Location found by content does not have matching building")
	assert.Equal(t, loc2.BuildingNumber, buildingNum, "Location found by content does not have matching building number")
	assert.Equal(t, loc2.StreetName, streetName, "Location found by content does not have matching street name")
	assert.Equal(t, loc2.Unit, unit, "Location found by content does not have matching unit")
	assert.Equal(t, loc2.POBox, poBox, "Location found by content does not have matching PO Box")
	assert.Equal(t, loc2.City, city, "Location found by content does not have matching city")
	assert.Equal(t, loc2.Locality, locality, "Location found by content does not have matching locality")
	assert.Equal(t, loc2.Province, province, "Location found by content does not have matching province")
	assert.Equal(t, loc2.Country, country, "Location found by content does not have matching country")
	assert.Equal(t, loc2.PostalCode, postalCode, "Location found by content does not have matching postal code")
	assert.Equal(t, loc2.GLN, gln, "Location found by content does not have matching GLN")

	for k, v := range map[string]string{
		"address":         address,
		"building":        building,
		"building_number": buildingNum,
		"street_name":     streetName,
		"unit":            unit,
		"city":            city,
		"locality":        locality,
		"province":        province,
		"country":         country,
		"postal_code":     postalCode,
	} {
		ents, err := db.FindEntitiesByContent(ctx, oam.Location, before, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the Location")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Location")
	}
}
