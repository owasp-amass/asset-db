// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
)

func TestCreateEdgeProperty(t *testing.T) {
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

	ip, err := db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: netip.MustParseAddr("104.20.44.163"),
		Type:    "IPv4",
	})
	assert.NoError(t, err, "Failed to create asset for the IPAddress: %v", err)
	assert.NotNil(t, ip, "Entity for the IPAddress should not be nil")

	rel := &oamdns.BasicDNSRelation{
		Name: "dns_record",
		Header: oamdns.RRHeader{
			RRType: 1,
			Class:  1,
			TTL:    3200,
		},
	}
	edge, err := db.CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: fqdn,
		ToEntity:   ip,
	})
	assert.NoError(t, err, "Failed to create edge for the DNS record")
	assert.NotNil(t, edge, "Edge should not be nil")

	prop := &oamgen.SourceProperty{
		Source:     "DNS",
		Confidence: 100,
	}
	tag, err := db.CreateEdgeProperty(ctx, edge, prop)
	assert.NoError(t, err, "Failed to create tag for the edge")
	assert.NotNil(t, tag, "Tag for the edge should not be nil")

	id, err := strconv.ParseInt(tag.ID, 10, 64)
	assert.NoError(t, err, "Edge tag ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Edge tag ID is not greater than zero")

	found, err := db.FindEdgeTagById(ctx, tag.ID)
	assert.NoError(t, err, "Failed to find edge tag by ID for the FQDN")
	assert.NotNil(t, found, "Edge tag found by ID for the FQDB should not be nil")
	assert.Equal(t, tag.ID, tag.ID, "Edge tag found by ID does not have matching IDs")
	assert.Equal(t, tag.CreatedAt, found.CreatedAt, "Edge CreatedAt found by ID for the DomainRecord does not match")
	assert.Equal(t, tag.LastSeen, found.LastSeen, "Edge LastSeen found by ID for the DomainRecord does not match")

	p, ok := tag.Property.(*oamgen.SourceProperty)
	assert.True(t, ok, "Tag found by ID is not of type *oamgen.SourceProperty")
	assert.Equal(t, prop.Source, p.Source, "SourceProperty found by ID does not have a matching Source")
	assert.Equal(t, prop.Confidence, p.Confidence, "SourceProperty found by ID does not have a matching Confidence")

	err = db.DeleteEdge(ctx, edge.ID)
	assert.NoError(t, err, "Failed to delete edge by ID for the FQDN")

	_, err = db.FindEdgeTagById(ctx, tag.ID)
	assert.Error(t, err, "Expected error when finding edge tag removed by cascading deletion")
}

func TestFindEdgeTags(t *testing.T) {
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

	ip, err := db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: netip.MustParseAddr("104.20.44.163"),
		Type:    "IPv4",
	})
	assert.NoError(t, err, "Failed to create asset for the IPAddress")
	assert.NotNil(t, ip, "Entity for the IPAddress should not be nil")

	rel := &oamdns.BasicDNSRelation{
		Name: "dns_record",
		Header: oamdns.RRHeader{
			RRType: 1,
			Class:  1,
			TTL:    3200,
		},
	}
	edge, err := db.CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: fqdn,
		ToEntity:   ip,
	})
	assert.NoError(t, err, "Failed to create edge for the DNS record")
	assert.NotNil(t, edge, "Edge should not be nil")

	prop1 := &oamgen.SourceProperty{
		Source:     "DNS",
		Confidence: 100,
	}

	before1 := time.Now()
	time.Sleep(100 * time.Millisecond)
	tag1, err := db.CreateEdgeProperty(ctx, edge, prop1)
	assert.NoError(t, err, "Failed to create tag for the edge")
	assert.NotNil(t, tag1, "Tag for the edge should not be nil")
	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()

	time.Sleep(time.Second)

	prop2 := &oamgen.SimpleProperty{
		PropertyName:  "fake",
		PropertyValue: "fake value",
	}

	before2 := time.Now()
	time.Sleep(100 * time.Millisecond)
	tag2, err := db.CreateEdgeProperty(ctx, edge, prop2)
	assert.NoError(t, err, "Failed to create tag for the edge")
	assert.NotNil(t, tag2, "Tag for the edge should not be nil")
	time.Sleep(100 * time.Millisecond)
	after2 := time.Now()

	tests := map[string]struct {
		edge   *dbt.Edge
		before time.Time
		after  time.Time
		since  time.Time
		names  []string
		count  int
	}{
		"edge": {
			edge:   edge,
			before: before1,
			after:  after2,
			since:  time.Time{},
			names:  []string{"DNS", "fake"},
			count:  2,
		},
		"edge since before1": {
			edge:   edge,
			before: before1,
			after:  after2,
			since:  before1,
			names:  nil,
			count:  2,
		},
		"edge since before2": {
			edge:   edge,
			before: before2,
			after:  after2,
			since:  before2,
			count:  1,
		},
		"edge since after2": {
			edge:   edge,
			before: before1,
			after:  after1,
			since:  after2,
			count:  0,
		},
		"edge with name dns_record": {
			edge:   edge,
			before: before1,
			after:  after1,
			since:  time.Time{},
			names:  []string{"DNS"},
			count:  1,
		},
		"edge with name fake": {
			edge:   edge,
			before: before2,
			after:  after2,
			since:  time.Time{},
			names:  []string{"fake"},
			count:  1,
		},
	}

	for tname, test := range tests {
		tags, err := db.FindEdgeTags(ctx, test.edge, test.since, test.names...)
		if test.count == 0 {
			assert.Error(t, err, "Expected error for "+tname)
			continue
		} else {
			assert.NoError(t, err, "Failed to get edge tags for "+tname)
			assert.Len(t, tags, test.count, "Unexpected number of edge tags for "+tname)
		}

		for _, tag := range tags {
			id, err := strconv.ParseInt(tag.ID, 10, 64)
			assert.NoError(t, err, "Tag ID is not a valid integer")
			assert.Greater(t, id, int64(0), "Tag ID is not greater than zero")
			assert.WithinRange(t, tag.CreatedAt, test.before, test.after, "Tag CreateAt does not fall within range for "+tname)
			assert.WithinRange(t, tag.LastSeen, test.before, test.after, "Tag LastSeen does not fall within range for "+tname)

			switch prop := tag.Property.(type) {
			case *oamgen.SourceProperty:
				assert.Equal(t, prop.Name(), prop1.Name(), "Tag does not have a matching name for "+tname)
				assert.Equal(t, prop.Value(), prop1.Value(), "Tag does not have a matching value for "+tname)
			case *oamgen.SimpleProperty:
				assert.Equal(t, prop.Name(), prop2.Name(), "Tag does not have a matching name for "+tname)
				assert.Equal(t, prop.Value(), prop2.Value(), "Tag does not have a matching value for "+tname)
			default:
				t.Errorf("Tag Property has an unexpected type for %s", tname)
			}
		}
	}

	for name, tag := range map[string]*dbt.EdgeTag{
		"tag1": tag1,
		"tag2": tag2,
	} {
		err = db.DeleteEdgeTag(ctx, tag.ID)
		assert.NoError(t, err, "Failed to delete "+name+" by ID")

		_, err = db.FindEdgeTagById(ctx, tag.ID)
		assert.Error(t, err, "Expected error when finding "+name+" removed by deletion")
	}
}

func BenchmarkFindEdgeTagByID(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	a1, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "test.com"})
	assert.NoError(b, err, "Failed to create the first FQDN asset")

	a2, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "www.test.com"})
	assert.NoError(b, err, "Failed to create the second FQDN asset")

	edge, err := db.CreateEdge(context.Background(), &dbt.Edge{
		Relation:   &oamdns.BasicDNSRelation{Name: "dns_record"},
		FromEntity: a1,
		ToEntity:   a2,
	})
	assert.NoError(b, err, "Failed to create the edge")

	var ids []string
	for i := range int64(1000) {
		prop, err := db.CreateEdgeProperty(context.Background(), edge, &oamgen.SimpleProperty{
			PropertyName:  "prop",
			PropertyValue: fmt.Sprintf("value%d", i),
		})
		assert.NoError(b, err, "Failed to create the edge property")
		ids = append(ids, prop.ID)
	}

	idx := int64(rand.Intn(1000))
	for b.Loop() {
		_, _ = db.FindEdgeTagById(context.Background(), ids[idx])
		idx = (idx + 1) % 1000
	}
}

func BenchmarkFindEdgeTags(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	a1, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "test.com"})
	assert.NoError(b, err, "Failed to create the first FQDN asset")

	a2, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "www.test.com"})
	assert.NoError(b, err, "Failed to create the second FQDN asset")

	edge, err := db.CreateEdge(context.Background(), &dbt.Edge{
		Relation:   &oamdns.BasicDNSRelation{Name: "dns_record"},
		FromEntity: a1,
		ToEntity:   a2,
	})
	assert.NoError(b, err, "Failed to create the edge")

	var names []string
	for i := range int64(1000) {
		tag, err := db.CreateEdgeProperty(context.Background(), edge, &oamgen.SimpleProperty{
			PropertyName:  fmt.Sprintf("prop%d", i),
			PropertyValue: "blahblah",
		})
		assert.NoError(b, err, "Failed to create the edge property")
		names = append(names, tag.Property.Name())
	}

	idx := int64(rand.Intn(1000))
	for b.Loop() {
		_, _ = db.FindEdgeTags(context.Background(), edge, time.Time{}, names[idx])
		idx = (idx + 1) % 1000
	}
}

func BenchmarkFindEdgeTagsWithSince(b *testing.B) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(b, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(b, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	a1, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "test.com"})
	assert.NoError(b, err, "Failed to create the first FQDN asset")

	a2, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "www.test.com"})
	assert.NoError(b, err, "Failed to create the second FQDN asset")

	edge, err := db.CreateEdge(context.Background(), &dbt.Edge{
		Relation:   &oamdns.BasicDNSRelation{Name: "dns_record"},
		FromEntity: a1,
		ToEntity:   a2,
	})
	assert.NoError(b, err, "Failed to create the edge")

	var since time.Time
	for i := range int64(1000) {
		_, err := db.CreateEdgeProperty(context.Background(), edge, &oamgen.SimpleProperty{
			PropertyName:  fmt.Sprintf("prop%d", i),
			PropertyValue: "blahblah",
		})
		assert.NoError(b, err, "Failed to create the edge property")

		if i == 950 {
			since = time.Now()
			time.Sleep(100 * time.Millisecond)
		}
	}

	for b.Loop() {
		_, _ = db.FindEdgeTags(context.Background(), edge, since)
	}
}
