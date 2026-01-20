// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/caffix/stringset"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
)

func TestFindEntitiesByType(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before1 := time.Now()
	time.Sleep(100 * time.Millisecond)
	set1 := stringset.New("example.com", "test.com", "sample.org")
	for _, name := range set1.Slice() {
		fqdn, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
		assert.NoError(t, err, "Failed to create FQDN '%s'", name)
		assert.NotNil(t, fqdn, "Entity for the FQDN '%s' should not be nil", name)
	}
	ip1, err := db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: netip.MustParseAddr("104.20.44.163"),
		Type:    "IPv4",
	})
	assert.NoError(t, err, "Failed to create asset for the IPAddress")
	assert.NotNil(t, ip1, "Entity for the IPAddress should not be nil")
	ip1set := stringset.New("104.20.44.163")
	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()

	time.Sleep(1 * time.Second)

	before2 := time.Now()
	time.Sleep(100 * time.Millisecond)
	set2 := stringset.New("example.net", "demo.com", "website.org")
	for _, name := range set2.Slice() {
		fqdn, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
		assert.NoError(t, err, "Failed to create FQDN '%s'", name)
		assert.NotNil(t, fqdn, "Entity for the FQDN '%s' should not be nil", name)
	}
	ip2, err := db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: netip.MustParseAddr("172.66.157.115"),
		Type:    "IPv4",
	})
	assert.NoError(t, err, "Failed to create asset for the IPAddress")
	assert.NotNil(t, ip2, "Entity for the IPAddress should not be nil")
	ip2set := stringset.New("172.66.157.115")
	time.Sleep(100 * time.Millisecond)
	after2 := time.Now()

	tests := map[string]struct {
		atype  oam.AssetType
		before time.Time
		after  time.Time
		since  time.Time
		sets   []*stringset.Set
		count  int
	}{
		"all fqdns": {
			atype:  oam.FQDN,
			before: before1,
			after:  after2,
			since:  before1,
			sets:   []*stringset.Set{set1, set2},
			count:  6,
		},
		"ips since before1": {
			atype:  oam.IPAddress,
			before: before1,
			after:  after2,
			since:  before1,
			sets:   []*stringset.Set{ip1set, ip2set},
			count:  2,
		},
		"fqdns since before2": {
			atype:  oam.FQDN,
			before: before2,
			after:  after2,
			since:  before2,
			sets:   []*stringset.Set{set2},
			count:  3,
		},
		"fqdns since after2": {
			atype:  oam.FQDN,
			before: before1,
			after:  after1,
			since:  after2,
			sets:   []*stringset.Set{},
			count:  0,
		},
		"ips since before2": {
			atype:  oam.IPAddress,
			before: before2,
			after:  after2,
			since:  before2,
			sets:   []*stringset.Set{ip2set},
			count:  1,
		},
		"ips since after2": {
			atype:  oam.IPAddress,
			before: before2,
			after:  after2,
			since:  after2,
			sets:   []*stringset.Set{},
			count:  0,
		},
	}

	for tname, test := range tests {
		entities, err := db.FindEntitiesByType(ctx, test.atype, test.since, 0)
		if test.count == 0 {
			assert.Error(t, err, "Expected error for "+tname)
			continue
		} else {
			assert.NoError(t, err, "Failed to get entities for "+tname)
			assert.Len(t, entities, test.count, "Unexpected number of entities for "+tname)
		}

		for _, entity := range entities {
			id, err := strconv.ParseInt(entity.ID, 10, 64)
			assert.NoError(t, err, "Entity ID is not a valid integer")
			assert.Greater(t, id, int64(0), "Entity ID is not greater than zero")
			assert.WithinRange(t, entity.CreatedAt, test.before, test.after, "Entity CreatedAt does not fall within range for "+tname)
			assert.WithinRange(t, entity.LastSeen, test.before, test.after, "Entity LastSeen does not fall within range for "+tname)

			switch a := entity.Asset.(type) {
			case *oamdns.FQDN:
				var found bool
				for _, s := range test.sets {
					if s.Has(a.Name) {
						found = true
						break
					}
				}
				if !found {
					assert.Fail(t, "FQDN not found in expected set for "+tname, a.Name)
				}
			case *oamnet.IPAddress:
				var found bool
				for _, s := range test.sets {
					if s.Has(a.Address.String()) {
						found = true
						break
					}
				}
				if !found {
					assert.Fail(t, "IP address not found in expected set for "+tname, a.Address.String())
				}
			default:
				t.Errorf("Entity Asset has an unexpected type for %s", tname)
			}
		}
	}
}

func BenchmarkFindEntityByID(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	var ids []string
	for i := range int64(1000) {
		a, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: fmt.Sprintf("www%d.example.com", i)})
		assert.NoError(b, err, "Failed to create the in-memory sqlite database")
		ids = append(ids, a.ID)
	}

	var i int64
	idx := int64(rand.Intn(1000))
	for b.Loop() {
		_, _ = db.FindEntityById(context.Background(), ids[idx])
		i = (i + 1) % 1000
	}
}

func BenchmarkFindEntitiesByContent(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	var names []string
	for i := range int64(1000) {
		n := fmt.Sprintf("www%d.example.com", i)
		_, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: n})
		assert.NoError(b, err, "Failed to create the in-memory sqlite database")
		names = append(names, n)
	}

	var i int64
	idx := int64(rand.Intn(1000))
	for b.Loop() {
		_, _ = db.FindEntitiesByContent(context.Background(), oam.FQDN, time.Time{}, 0, dbt.ContentFilters{
			"name": names[idx],
		})
		i = (i + 1) % 1000
	}
}

func BenchmarkFindEntitiesByContentWithSince(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	var names []string
	since := time.Now()
	time.Sleep(100 * time.Millisecond)
	for i := range int64(1000) {
		n := fmt.Sprintf("www%d.example.com", i)
		_, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: n})
		assert.NoError(b, err, "Failed to create the in-memory sqlite database")
		names = append(names, n)
	}

	var i int64
	idx := int64(rand.Intn(1000))
	for b.Loop() {
		_, _ = db.FindEntitiesByContent(context.Background(), oam.FQDN, since, 0, dbt.ContentFilters{
			"name": names[idx],
		})
		i = (i + 1) % 1000
	}
}

func BenchmarkFindEntitiesByType(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	var since time.Time
	for i := range int64(1000) {
		n := fmt.Sprintf("www%d.example.com", i)

		_, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: n})
		assert.NoError(b, err, "Failed to create the in-memory sqlite database")

		if i == 950 {
			since = time.Now()
			time.Sleep(100 * time.Millisecond)
		}
	}

	for b.Loop() {
		_, _ = db.FindEntitiesByType(context.Background(), oam.FQDN, since, 0)
	}
}
