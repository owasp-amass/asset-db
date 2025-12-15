// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
)

func TestCreateEntityProperty(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	fqdn, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err, "Failed to create asset for the FQDN")
	assert.NotNil(t, fqdn, "Entity for the FQDN should not be nil")

	prop := &oamdns.DNSRecordProperty{
		PropertyName: "dns_record",
		Header: oamdns.RRHeader{
			RRType: 16,
			Class:  1,
			TTL:    8400,
		},
		Data: "fake txt record",
	}
	tag, err := db.CreateEntityProperty(ctx, fqdn, prop)
	assert.NoError(t, err, "Failed to create tag for the FQDN")
	assert.NotNil(t, tag, "Tag for the FQDN should not be nil")

	id, err := strconv.ParseInt(tag.ID, 10, 64)
	assert.NoError(t, err, "Entity tag ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Entity tag ID is not greater than zero")

	found, err := db.FindEntityTagById(ctx, tag.ID)
	assert.NoError(t, err, "Failed to find entity tag by ID for the FQDN")
	assert.NotNil(t, found, "Entity tag found by ID for the FQDB should not be nil")
	assert.Equal(t, tag.ID, tag.ID, "Entity tag found by ID does not have matching IDs")
	assert.Equal(t, tag.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the DomainRecord does not match")
	assert.Equal(t, tag.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the DomainRecord does not match")

	p, ok := tag.Property.(*oamdns.DNSRecordProperty)
	assert.True(t, ok, "Tag found by ID is not of type *oamdns.DNSRecordProperty")
	assert.Equal(t, prop.Name(), p.Name(), "DNSRecordProperty found by ID does not have a matching Name")
	assert.Equal(t, prop.Header.RRType, p.Header.RRType, "DNSRecordProperty found by ID does not have a matching Header.RRType")
	assert.Equal(t, prop.Header.Class, p.Header.Class, "DNSRecordProperty found by ID does not have a matching Header.Class")
	assert.Equal(t, prop.Header.TTL, p.Header.TTL, "DNSRecordProperty found by ID does not have a matching Header.TTL")
	assert.Equal(t, prop.Value(), p.Value(), "DNSRecordProperty found by ID does not have a matching Value")

	err = db.DeleteEntity(ctx, fqdn.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the FQDN")

	_, err = db.FindEntityTagById(ctx, tag.ID)
	assert.Error(t, err, "Expected error when finding entity tag removed by cascading deletion")
}

func TestFindEntityTags(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fqdn, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err, "Failed to create asset for the FQDN")
	assert.NotNil(t, fqdn, "Entity for the FQDN should not be nil")

	prop1 := &oamdns.DNSRecordProperty{
		PropertyName: "dns_record",
		Header: oamdns.RRHeader{
			RRType: 16,
			Class:  1,
			TTL:    8400,
		},
		Data: "fake txt record",
	}

	before1 := time.Now()
	time.Sleep(100 * time.Millisecond)
	tag1, err := db.CreateEntityProperty(ctx, fqdn, prop1)
	assert.NoError(t, err, "Failed to create tag for the FQDN")
	assert.NotNil(t, tag1, "Tag for the FQDN should not be nil")
	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()

	time.Sleep(time.Second)

	prop2 := &oamgen.SimpleProperty{
		PropertyName:  "fake",
		PropertyValue: "fake value",
	}

	before2 := time.Now()
	time.Sleep(100 * time.Millisecond)
	tag2, err := db.CreateEntityProperty(ctx, fqdn, prop2)
	assert.NoError(t, err, "Failed to create tag for the FQDN")
	assert.NotNil(t, tag2, "Tag for the FQDN should not be nil")
	time.Sleep(100 * time.Millisecond)
	after2 := time.Now()

	tests := map[string]struct {
		entity *dbt.Entity
		before time.Time
		after  time.Time
		since  time.Time
		names  []string
		count  int
	}{
		"fqdn": {
			entity: fqdn,
			before: before1,
			after:  after2,
			since:  time.Time{},
			names:  []string{"dns_record", "fake"},
			count:  2,
		},
		"fqdn since before1": {
			entity: fqdn,
			before: before1,
			after:  after2,
			since:  before1,
			names:  nil,
			count:  2,
		},
		"fqdn since before2": {
			entity: fqdn,
			before: before2,
			after:  after2,
			since:  before2,
			count:  1,
		},
		"fqdn since after2": {
			entity: fqdn,
			before: before1,
			after:  after1,
			since:  after2,
			count:  0,
		},
		"fqdn with name dns_record": {
			entity: fqdn,
			before: before1,
			after:  after1,
			since:  time.Time{},
			names:  []string{"dns_record"},
			count:  1,
		},
		"fqdn with name fake": {
			entity: fqdn,
			before: before2,
			after:  after2,
			since:  time.Time{},
			names:  []string{"fake"},
			count:  1,
		},
	}

	for tname, test := range tests {
		tags, err := db.FindEntityTags(ctx, test.entity, test.since, test.names...)
		if test.count == 0 {
			assert.Error(t, err, "Expected error for "+tname)
			continue
		} else {
			assert.NoError(t, err, "Failed to get entity tags for "+tname)
			assert.Len(t, tags, test.count, "Unexpected number of entity tags for "+tname)
		}

		for _, tag := range tags {
			id, err := strconv.ParseInt(tag.ID, 10, 64)
			assert.NoError(t, err, "Tag ID is not a valid integer")
			assert.Greater(t, id, int64(0), "Tag ID is not greater than zero")
			assert.WithinRange(t, tag.CreatedAt, test.before, test.after, "Tag CreateAt does not fall within range for "+tname)
			assert.WithinRange(t, tag.LastSeen, test.before, test.after, "Tag LastSeen does not fall within range for "+tname)

			switch prop := tag.Property.(type) {
			case *oamdns.DNSRecordProperty:
				assert.Equal(t, prop.Name(), prop1.Name(), "Tag does not have a matching name for "+tname)
				assert.Equal(t, prop.Value(), prop1.Value(), "Tag does not have a matching value for "+tname)
				assert.Equal(t, prop.Header.RRType, prop1.Header.RRType, "Tag found by ID does not have a matching Header.RRType")
				assert.Equal(t, prop.Header.Class, prop1.Header.Class, "Tag found by ID does not have a matching Header.Class")
				assert.Equal(t, prop.Header.TTL, prop1.Header.TTL, "Tag found by ID does not have a matching Header.TTL")
			case *oamgen.SimpleProperty:
				assert.Equal(t, prop.Name(), prop2.Name(), "Tag does not have a matching name for "+tname)
				assert.Equal(t, prop.Value(), prop2.Value(), "Tag does not have a matching value for "+tname)
			default:
				t.Errorf("Tag Property has an unexpected type for %s", tname)
			}
		}
	}

	for name, tag := range map[string]*dbt.EntityTag{
		"tag1": tag1,
		"tag2": tag2,
	} {
		err = db.DeleteEntityTag(ctx, tag.ID)
		assert.NoError(t, err, "Failed to delete "+name+" by ID")

		_, err = db.FindEntityTagById(ctx, tag.ID)
		assert.Error(t, err, "Expected error when finding "+name+" removed by deletion")
	}
}

func BenchmarkFindEntityTagByID(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	a, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "test.com"})
	assert.NoError(b, err, "Failed to create the FQDN asset")

	var ids []string
	for i := range int64(1000) {
		prop, err := db.CreateEntityProperty(context.Background(), a, &oamgen.SimpleProperty{
			PropertyName:  "prop",
			PropertyValue: fmt.Sprintf("value%d", i),
		})
		assert.NoError(b, err, "Failed to create the entity property")
		ids = append(ids, prop.ID)
	}

	idx := int64(rand.Intn(1000))
	for b.Loop() {
		_, _ = db.FindEntityTagById(context.Background(), ids[idx])
		idx = (idx + 1) % 1000
	}
}

func BenchmarkFindEntityTags(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	a, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "test.com"})
	assert.NoError(b, err, "Failed to create the FQDN asset")

	var names []string
	for i := range int64(1000) {
		tag, err := db.CreateEntityProperty(context.Background(), a, &oamgen.SimpleProperty{
			PropertyName:  fmt.Sprintf("prop%d", i),
			PropertyValue: "blahblah",
		})
		assert.NoError(b, err, "Failed to create the entity property")
		names = append(names, tag.Property.Name())
	}

	idx := int64(rand.Intn(1000))
	for b.Loop() {
		_, _ = db.FindEntityTags(context.Background(), a, time.Time{}, names[idx])
		idx = (idx + 1) % 1000
	}
}

func BenchmarkFindEntityTagsWithSince(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	a, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "test.com"})
	assert.NoError(b, err, "Failed to create the FQDN asset")

	var since time.Time
	for i := range int64(1000) {
		_, err := db.CreateEntityProperty(context.Background(), a, &oamgen.SimpleProperty{
			PropertyName:  fmt.Sprintf("prop%d", i),
			PropertyValue: "blahblah",
		})
		assert.NoError(b, err, "Failed to create the entity property")

		if i == 950 {
			since = time.Now()
			time.Sleep(100 * time.Millisecond)
		}
	}

	for b.Loop() {
		_, _ = db.FindEntityTags(context.Background(), a, since)
	}
}
