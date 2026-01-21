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
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForContactRecord(t *testing.T) {
	db, err := New(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	discovered := "Probably some URL"
	cr, err := db.CreateAsset(ctx, &oamcon.ContactRecord{DiscoveredAt: discovered})
	assert.NoError(t, err, "Failed to create asset for the ContactRecord")
	assert.NotNil(t, cr, "Entity for the ContactRecord should not be nil")
	time.Sleep(100 * time.Millisecond)
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
	db, err := New(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	discovered := "Probably some URL"
	cr, err := db.CreateAsset(ctx, &oamcon.ContactRecord{DiscoveredAt: discovered})
	assert.NoError(t, err, "Failed to create asset for the ContactRecord")
	assert.NotNil(t, cr, "Entity for the ContactRecord should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = db.FindEntitiesByContent(ctx, oam.ContactRecord, after, 1, dbt.ContentFilters{
		"discovered_at": discovered,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := db.FindEntitiesByContent(ctx, oam.ContactRecord, before, 1, dbt.ContentFilters{
		"discovered_at": discovered,
	})
	assert.NoError(t, err, "Failed to find entity by content for the ContactRecord")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the ContactRecord should not be nil")

	cr2, ok := found.Asset.(*oamcon.ContactRecord)
	assert.True(t, ok, "ContactRecord found by content is not of type *oamcon.ContactRecord")
	assert.Equal(t, found.ID, cr.ID, "ContactRecord found by content does not have matching IDs")
	assert.Equal(t, cr2.DiscoveredAt, discovered, "ContactRecord DiscoveredAt found by content does not match")

	ents, err = db.FindEntitiesByContent(ctx, oam.ContactRecord, before, 0, dbt.ContentFilters{
		"discovered_at": discovered,
	})
	assert.NoError(t, err, "Failed to find entities by content for the ContactRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the ContactRecord")
}

func TestFindEntitiesByTypeForContactRecord(t *testing.T) {
	db, err := New(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	atype := oam.ContactRecord
	atypestr := "ContactRecord"
	key1 := "https://owasp.org/fake1.html"
	ent, err := db.CreateAsset(ctx, &oamcon.ContactRecord{DiscoveredAt: key1})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := "https://owasp.org/fake2.html"
	ent, err = db.CreateAsset(ctx, &oamcon.ContactRecord{DiscoveredAt: key2})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "https://owasp.org/fake3.html"
	ent, err = db.CreateAsset(ctx, &oamcon.ContactRecord{DiscoveredAt: key3})
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
