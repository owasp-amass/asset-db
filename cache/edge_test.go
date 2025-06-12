// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
)

func TestCreateEdge(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		_ = db1.Close()
		_ = db2.Close()
		_ = os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer func() { _ = c.Close() }()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	after := ctime.Add(2 * time.Second)

	edge, err := createTestEdge(c, ctime)
	assert.NoError(t, err)
	assert.WithinRange(t, edge.CreatedAt, before, after)
	assert.WithinRange(t, edge.LastSeen, before, after)

	if tags, err := c.cache.GetEdgeTags(edge, time.Time{}, "cache_create_edge"); err != nil || len(tags) != 1 {
		t.Errorf("failed to create the cache tag:")
	}

	time.Sleep(250 * time.Millisecond)
	dbents, err := c.db.FindEntitiesByContent(edge.FromEntity.Asset, before)
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	dbedges, err := c.db.OutgoingEdges(dbent, before, "dns_record")
	assert.NoError(t, err)

	if num := len(dbedges); num != 1 {
		t.Errorf("failed to return the corrent number of edges: %d", num)
	}
	dbedge := dbedges[0]

	if !reflect.DeepEqual(edge.Relation, dbedge.Relation) {
		t.Errorf("DeepEqual failed for the relations in the two edges")
	}
	assert.WithinRange(t, dbedge.CreatedAt, before, after)
	assert.WithinRange(t, dbedge.LastSeen, before, after)
}

func createTestEdge(cache *Cache, ctime time.Time) (*types.Edge, error) {
	entity1, err := cache.CreateEntity(&types.Entity{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Asset:     &dns.FQDN{Name: "owasp.org"},
	})
	if err != nil {
		return nil, err
	}

	entity2, err := cache.CreateEntity(&types.Entity{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Asset:     &dns.FQDN{Name: "www.owasp.org"},
	})
	if err != nil {
		return nil, err
	}

	edge, err := cache.CreateEdge(&types.Edge{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Relation: &dns.BasicDNSRelation{
			Name: "dns_record",
			Header: dns.RRHeader{
				RRType: 5,
				Class:  1,
				TTL:    3600,
			},
		},
		FromEntity: entity2,
		ToEntity:   entity1,
	})
	if err != nil {
		return nil, err
	}

	edge.FromEntity = entity2
	edge.ToEntity = entity1
	return edge, nil
}

func TestFindEdgeById(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		_ = db1.Close()
		_ = db2.Close()
		_ = os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer func() { _ = c.Close() }()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)

	edge, err := createTestEdge(c, ctime)
	assert.NoError(t, err)

	e, err := c.FindEdgeById(edge.ID)
	assert.NoError(t, err)

	if !reflect.DeepEqual(edge.Relation, e.Relation) {
		t.Errorf("DeepEqual failed for the relation in the two edges")
	}
}

func TestIncomingEdges(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		_ = db1.Close()
		_ = db2.Close()
		_ = os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer func() { _ = c.Close() }()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	from, err := c.CreateEntity(&types.Entity{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Asset:     &dns.FQDN{Name: "caffix.com"},
	})
	assert.NoError(t, err)
	time.Sleep(250 * time.Millisecond)

	dbfrom, err := c.db.FindEntitiesByContent(from.Asset, time.Time{})
	assert.NoError(t, err)

	set1 := stringset.New()
	defer set1.Close()
	// add some old stuff to the database
	var entities1 []*types.Entity
	for _, name := range []string{"owasp.org", "utica.edu", "sunypoly.edu"} {
		set1.Insert(name)
		e, err := c.db.CreateEntity(&types.Entity{
			CreatedAt: ctime,
			LastSeen:  ctime,
			Asset:     &dns.FQDN{Name: name},
		})
		assert.NoError(t, err)
		_, err = c.db.CreateEdge(&types.Edge{
			CreatedAt:  ctime,
			LastSeen:   ctime,
			Relation:   general.SimpleRelation{Name: "node"},
			FromEntity: dbfrom[0],
			ToEntity:   e,
		})
		assert.NoError(t, err)
		entities1 = append(entities1, e)
	}

	set2 := stringset.New()
	defer set2.Close()
	// add some new stuff to the database
	var entities2 []*types.Entity
	for _, name := range []string{"www.owasp.org", "www.utica.edu", "www.sunypoly.edu"} {
		set2.Insert(name)
		e, err := c.CreateAsset(&dns.FQDN{Name: name})
		assert.NoError(t, err)
		_, err = c.CreateEdge(&types.Edge{
			Relation:   general.SimpleRelation{Name: "node"},
			FromEntity: from,
			ToEntity:   e,
		})
		assert.NoError(t, err)
		entities2 = append(entities2, e)
	}
	after := time.Now().Add(time.Second)

	// some tests that shouldn't return anything
	_, err = c.IncomingEdges(entities2[0], after)
	assert.Error(t, err)
	// there shouldn't be a tag for this entity, since it didn't require the database
	_, err = c.cache.GetEntityTags(entities2[0], time.Time{}, "cache_incoming_edges")
	assert.Error(t, err)

	for _, entity := range entities2 {
		edges, err := c.IncomingEdges(entity, c.StartTime(), "node")
		assert.NoError(t, err)
		if len(edges) != 1 {
			t.Errorf("%s had the incorrect number of incoming edges", entity.Asset.Key())
		}
		set2.Remove(entity.Asset.Key())
	}

	// only entities from set2 should have been removed
	if set1.Len() != 3 || set2.Len() != 0 {
		t.Errorf("first request failed to produce the correct edges")
	}
	// there shouldn't be a tag for this entity, since it didn't require the database
	_, err = c.cache.GetEntityTags(entities2[0], time.Time{}, "cache_incoming_edges")
	assert.Error(t, err)

	var rentity *types.Entity
	for _, entity := range entities1 {
		e, err := c.FindEntitiesByContent(entity.Asset, time.Time{})
		assert.NoError(t, err)
		rentity = e[0]
		edges, err := c.IncomingEdges(rentity, before, "node")
		assert.NoError(t, err)
		if len(edges) != 1 {
			t.Errorf("%s had the incorrect number of incoming edges", rentity.Asset.Key())
		}
		set1.Remove(rentity.Asset.Key())
	}

	// all entities should now be been removed
	if set1.Len() != 0 || set2.Len() != 0 {
		t.Errorf("second request failed to produce the correct entities")
	}
	// there should be a tag for this entity
	tags, err := c.cache.GetEntityTags(rentity, time.Time{}, "cache_incoming_edges")
	assert.NoError(t, err)
	if len(tags) != 1 {
		t.Errorf("second request failed to produce the expected number of entity tags")
	}
	ts := tags[0].Property.(*types.CacheProperty).Timestamp

	tagtime, err := time.Parse(time.RFC3339Nano, ts)
	assert.NoError(t, err)
	assert.WithinRange(t, tagtime, before, after)
}

func TestOutgoingEdges(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		_ = db1.Close()
		_ = db2.Close()
		_ = os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer func() { _ = c.Close() }()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	from, err := c.CreateEntity(&types.Entity{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Asset:     &dns.FQDN{Name: "caffix.com"},
	})
	assert.NoError(t, err)
	time.Sleep(250 * time.Millisecond)

	dbfrom, err := c.db.FindEntitiesByContent(from.Asset, time.Time{})
	assert.NoError(t, err)

	set1 := stringset.New()
	defer set1.Close()
	// add some old stuff to the database
	for _, name := range []string{"owasp.org", "utica.edu", "sunypoly.edu"} {
		set1.Insert(name)
		e, err := c.db.CreateEntity(&types.Entity{
			CreatedAt: ctime,
			LastSeen:  ctime,
			Asset:     &dns.FQDN{Name: name},
		})
		assert.NoError(t, err)
		_, err = c.db.CreateEdge(&types.Edge{
			CreatedAt:  ctime,
			LastSeen:   ctime,
			Relation:   general.SimpleRelation{Name: "node"},
			FromEntity: dbfrom[0],
			ToEntity:   e,
		})
		assert.NoError(t, err)
	}

	set2 := stringset.New()
	defer set2.Close()
	// add some new stuff to the database
	for _, name := range []string{"www.owasp.org", "www.utica.edu", "www.sunypoly.edu"} {
		set2.Insert(name)
		e, err := c.CreateAsset(&dns.FQDN{Name: name})
		assert.NoError(t, err)
		_, err = c.CreateEdge(&types.Edge{
			Relation:   general.SimpleRelation{Name: "node"},
			FromEntity: from,
			ToEntity:   e,
		})
		assert.NoError(t, err)
	}
	after := time.Now().Add(time.Second)

	// some tests that shouldn't return anything
	_, err = c.OutgoingEdges(from, after)
	assert.Error(t, err)
	// there shouldn't be a tag for this entity, since it didn't require the database
	_, err = c.cache.GetEntityTags(from, time.Time{}, "cache_outgoing_edges")
	assert.Error(t, err)

	edges, err := c.OutgoingEdges(from, c.StartTime(), "node")
	assert.NoError(t, err)
	if len(edges) != 3 {
		t.Errorf("incorrect number of outgoing edges")
	}

	for _, edge := range edges {
		e, err := c.FindEntityById(edge.ToEntity.ID)
		assert.NoError(t, err)
		set2.Remove(e.Asset.Key())
	}

	// only entities from set2 should have been removed
	if set1.Len() != 3 || set2.Len() != 0 {
		t.Errorf("first request failed to produce the correct edges")
	}
	// there shouldn't be a tag for this entity, since it didn't require the database
	_, err = c.cache.GetEntityTags(from, time.Time{}, "cache_outgoing_edges")
	assert.Error(t, err)

	edges, err = c.OutgoingEdges(from, before, "node")
	assert.NoError(t, err)
	if len(edges) != 6 {
		t.Errorf("incorrect number of outgoing edges")
	}

	for _, edge := range edges {
		e, err := c.FindEntityById(edge.ToEntity.ID)
		assert.NoError(t, err)
		set1.Remove(e.Asset.Key())
	}

	// all entities should now be been removed
	if set1.Len() != 0 || set2.Len() != 0 {
		t.Errorf("second request failed to produce the correct entities")
	}
	// there should be a tag for this entity
	tags, err := c.cache.GetEntityTags(from, time.Time{}, "cache_outgoing_edges")
	assert.NoError(t, err)
	if len(tags) != 1 {
		t.Errorf("second request failed to produce the expected number of entity tags")
	}
	ts := tags[0].Property.(*types.CacheProperty).Timestamp

	tagtime, err := time.Parse(time.RFC3339Nano, ts)
	assert.NoError(t, err)
	assert.WithinRange(t, tagtime, before, after)
}

func TestDeleteEdge(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		_ = db1.Close()
		_ = db2.Close()
		_ = os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer func() { _ = c.Close() }()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)

	edge, err := createTestEdge(c, ctime)
	assert.NoError(t, err)

	err = c.DeleteEdge(edge.ID)
	assert.NoError(t, err)

	_, err = c.cache.FindEdgeById(edge.ID)
	assert.Error(t, err)

	time.Sleep(250 * time.Millisecond)
	dbent, err := c.db.FindEntitiesByContent(edge.FromEntity.Asset, time.Time{})
	assert.NoError(t, err)
	_, err = c.db.OutgoingEdges(dbent[0], before, edge.Relation.Label())
	assert.Error(t, err)
}
