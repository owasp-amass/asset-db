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

func TestCreateAssetForPhone(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	ptype := oamcon.PhoneTypeMobile
	number := "+1-555-555-5555"
	e164 := "+15555555555"
	ca := "US"
	cc := 1
	ext := ""

	phone, err := db.CreateAsset(ctx, &oamcon.Phone{
		Type:          ptype,
		Raw:           number,
		E164:          e164,
		CountryAbbrev: ca,
		CountryCode:   cc,
		Ext:           ext,
	})
	assert.NoError(t, err, "Failed to create asset for the Phone")
	assert.NotNil(t, phone, "Entity for the Phone should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, phone.CreatedAt, before, after, "Phone entity CreatedAt is incorrect")
	assert.WithinRange(t, phone.LastSeen, before, after, "Phone entity LastSeen is incorrect")

	id, err := strconv.ParseInt(phone.ID, 10, 64)
	assert.NoError(t, err, "Phone entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Phone entity ID is not greater than zero")

	found, err := db.FindEntityById(ctx, phone.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Phone")
	assert.NotNil(t, found, "Entity found by ID for the Phone should not be nil")
	assert.Equal(t, phone.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Phone does not match")
	assert.Equal(t, phone.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Phone does not match")

	phone2, ok := found.Asset.(*oamcon.Phone)
	assert.True(t, ok, "Phone found by content is not of type *oamcon.Phone")
	assert.Equal(t, found.ID, phone.ID, "Phone found by content does not have matching IDs")
	assert.Equal(t, phone2.Type, ptype, "Phone found by content does not have matching type")
	assert.Equal(t, phone2.Raw, number, "Phone found by content does not have matching raw number")
	assert.Equal(t, phone2.E164, e164, "Phone found by content does not have matching E164 number")
	assert.Equal(t, phone2.CountryAbbrev, ca, "Phone found by content does not have matching country abbreviation")
	assert.Equal(t, phone2.CountryCode, cc, "Phone found by content does not have matching country code")
	assert.Equal(t, phone2.Ext, ext, "Phone found by content does not have matching extension")

	err = db.DeleteEntity(ctx, phone.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Phone")

	_, err = db.FindEntityById(ctx, phone.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Phone")
}

func TestFindEntitiesByContentForPhone(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	ptype := oamcon.PhoneTypeMobile
	number := "+1-555-555-5555"
	e164 := "+15555555555"
	ca := "US"
	cc := 1
	ext := ""

	phone, err := db.CreateAsset(ctx, &oamcon.Phone{
		Type:          ptype,
		Raw:           number,
		E164:          e164,
		CountryAbbrev: ca,
		CountryCode:   cc,
		Ext:           ext,
	})
	assert.NoError(t, err, "Failed to create asset for the Phone")
	assert.NotNil(t, phone, "Entity for the Phone should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = db.FindOneEntityByContent(ctx, oam.Phone, after, dbt.ContentFilters{
		"e164": e164,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := db.FindOneEntityByContent(ctx, oam.Phone, before, dbt.ContentFilters{
		"e164": e164,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Phone")
	assert.NotNil(t, found, "Entity found by content for the Phone should not be nil")

	phone2, ok := found.Asset.(*oamcon.Phone)
	assert.True(t, ok, "Phone found by content is not of type *oamcon.Phone")
	assert.Equal(t, found.ID, phone.ID, "Phone found by content does not have matching IDs")
	assert.Equal(t, phone2.Type, ptype, "Phone found by content does not have matching type")
	assert.Equal(t, phone2.Raw, number, "Phone found by content does not have matching raw number")
	assert.Equal(t, phone2.E164, e164, "Phone found by content does not have matching E164 number")
	assert.Equal(t, phone2.CountryAbbrev, ca, "Phone found by content does not have matching country abbreviation")
	assert.Equal(t, phone2.CountryCode, cc, "Phone found by content does not have matching country code")
	assert.Equal(t, phone2.Ext, ext, "Phone found by content does not have matching extension")

	ents, err := db.FindEntitiesByContent(ctx, oam.Phone, before, dbt.ContentFilters{
		"e164": e164,
	})
	assert.NoError(t, err, "Failed to find entities by content for the Phone")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Phone")

	ents, err = db.FindEntitiesByContent(ctx, oam.Phone, before, dbt.ContentFilters{
		"country_code": cc,
	})
	assert.NoError(t, err, "Failed to find entities by content for the Phone")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Phone")
}
