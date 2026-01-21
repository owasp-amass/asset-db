// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForIdentifier(t *testing.T) {
	db, err := New(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	idvalue := "someone@owasp.org"
	idtype := oamgen.EmailAddress
	unique_id := idtype + ":" + idvalue
	created := time.Now().Add(-24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	updated := time.Now().Add(-1 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	expiration := time.Now().Add(24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	status := "active"
	idasset, err := db.CreateAsset(ctx, &oamgen.Identifier{
		UniqueID:       unique_id,
		ID:             idvalue,
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

	found, err := db.FindEntityById(ctx, idasset.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Identifier")
	assert.NotNil(t, found, "Entity found by ID for the Identifier should not be nil")
	assert.Equal(t, idasset.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Identifier does not match")
	assert.Equal(t, idasset.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Identifier does not match")

	idasset2, ok := found.Asset.(*oamgen.Identifier)
	assert.True(t, ok, "Asset found by ID is not of type *oamgen.Identifier")
	assert.Equal(t, found.ID, idasset.ID, "Identifier found by Entity ID does not have matching IDs")
	assert.Equal(t, idasset2.UniqueID, unique_id, "Identifier found by ID does not have a matching UniqueID")
	assert.Equal(t, idasset2.ID, idvalue, "Identifier found by Entity ID does not have a matching ID value")
	assert.Equal(t, idasset2.Type, idtype, "Identifier found by Entity ID does not have a matching Type")
	assert.Equal(t, idasset2.CreationDate, created, "Identifier found by ID does not have a matching CreationDate")
	assert.Equal(t, idasset2.UpdatedDate, updated, "Identifier found by ID does not have a matching UpdatedDate")
	assert.Equal(t, idasset2.ExpirationDate, expiration, "Identifier found by ID does not have a matching ExpirationDate")
	assert.Equal(t, idasset2.Status, status, "Identifier found by ID does not have a matching Status")

	err = db.DeleteEntity(ctx, idasset.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Identifier")

	_, err = db.FindEntityById(ctx, idasset.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Identifier")
}

func TestFindEntitiesByContentForIdentifier(t *testing.T) {
	db, err := New(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	idvalue := "someone@owasp.org"
	idtype := oamgen.EmailAddress
	unique_id := idtype + ":" + idvalue
	created := time.Now().Add(-24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	updated := time.Now().Add(-1 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	expiration := time.Now().Add(24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05Z07:00")
	status := "active"
	idasset, err := db.CreateAsset(ctx, &oamgen.Identifier{
		UniqueID:       unique_id,
		ID:             idvalue,
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

	_, err = db.FindEntitiesByContent(ctx, oam.Identifier, after, 1, dbt.ContentFilters{
		"unique_id": unique_id,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := db.FindEntitiesByContent(ctx, oam.Identifier, before, 1, dbt.ContentFilters{
		"unique_id": unique_id,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Identifier")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the Identifier should not be nil")

	idasset2, ok := found.Asset.(*oamgen.Identifier)
	assert.True(t, ok, "Identifier found by content is not of type *oamgen.Identifier")
	assert.Equal(t, found.ID, idasset.ID, "Identifier found by content does not have matching IDs")
	assert.Equal(t, idasset2.UniqueID, unique_id, "Identifier found by Entity ID does not have a matching UniqueID")
	assert.Equal(t, idasset2.ID, idvalue, "Identifier found by Entity ID does not have a matching ID value")
	assert.Equal(t, idasset2.Type, idtype, "Identifier found by Entity ID does not have a matching Type")
	assert.Equal(t, idasset2.CreationDate, created, "Identifier found by Entity ID does not have a matching CreationDate")
	assert.Equal(t, idasset2.UpdatedDate, updated, "Identifier found by Entity ID does not have a matching UpdatedDate")
	assert.Equal(t, idasset2.ExpirationDate, expiration, "Identifier found by Entity ID does not have a matching ExpirationDate")
	assert.Equal(t, idasset2.Status, status, "Identifier found by Entity ID does not have a matching Status")

	ents, err = db.FindEntitiesByContent(ctx, oam.Identifier, before, 0, dbt.ContentFilters{
		"unique_id": unique_id,
	})
	assert.NoError(t, err, "Failed to find entities by content for the Identifier")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Identifier")

	ents, err = db.FindEntitiesByContent(ctx, oam.Identifier, before, 0, dbt.ContentFilters{
		"id_type": idtype,
	})
	assert.NoError(t, err, "Failed to find entities by content for the Identifier")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Identifier")
}

func TestFindEntitiesByTypeForIdentifier(t *testing.T) {
	db, err := New(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	atype := oam.Identifier
	atypestr := "Identifier"
	key1 := oamgen.EmailAddress + ":fake1@gmail.com"
	ent, err := db.CreateAsset(ctx, &oamgen.Identifier{
		UniqueID: key1,
		ID:       "fake1@gmail.com",
		Type:     oamgen.EmailAddress,
	})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := oamgen.EmailAddress + ":fake2@gmail.com"
	ent, err = db.CreateAsset(ctx, &oamgen.Identifier{
		UniqueID: key2,
		ID:       "fake2@gmail.com",
		Type:     oamgen.EmailAddress,
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := oamgen.EmailAddress + ":fake3@gmail.com"
	ent, err = db.CreateAsset(ctx, &oamgen.Identifier{
		UniqueID: key3,
		ID:       "fake3@gmail.com",
		Type:     oamgen.EmailAddress,
	})
	assert.NoError(t, err, "Failed to create asset for the third %s", atypestr)
	assert.NotNil(t, ent, "Entity for the third %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after23 := time.Now()

	for k, v := range map[string]struct {
		since    time.Time
		limit    int
		expected []string
	}{
		"find all since1": {
			since:    since1,
			limit:    3,
			expected: []string{key3, key2, key1},
		},
		"one out of all": {
			since:    since1,
			limit:    1,
			expected: []string{key3},
		},
		"two out of all": {
			since:    since1,
			limit:    2,
			expected: []string{key3, key2},
		},
		"find all after1": {
			since:    after1,
			limit:    3,
			expected: []string{key3, key2},
		},
		"one out of two and three": {
			since:    since23,
			limit:    1,
			expected: []string{key3},
		},
		"zero entities after23": {
			since:    after23,
			limit:    3,
			expected: []string{},
		},
		"no since returns error": {
			since:    time.Time{},
			limit:    0,
			expected: []string{},
		},
	} {
		ents, err := db.FindEntitiesByType(ctx, atype, v.since, v.limit)

		var got []string
		for _, ent := range ents {
			got = append(got, ent.Asset.Key())
		}

		if len(v.expected) > 0 {
			assert.NoError(t, err, "The %s test failed for %s: expected %v: got: %v", k, atypestr, v.expected, got)
		} else {
			assert.Error(t, err, "The %s test failed for %s: zero findings should return an error", k, atypestr)
		}

		assert.Len(t, ents, len(v.expected),
			"The %s test expected to find exactly %d entities for %s: got: %d", k, v.limit, atypestr, len(ents),
		)
	}
}
