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

func TestCreateEdgeTag(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer c.Close()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	after := ctime.Add(2 * time.Second)
	entity, err := c.CreateAsset(&dns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)
	tag, err := c.CreateEntityTag(entity, &types.EntityTag{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Property: &general.SimpleProperty{
			PropertyName:  "test",
			PropertyValue: "foobar",
		},
		Entity: entity,
	})
	assert.NoError(t, err)

	if tag.CreatedAt.Before(before) || tag.CreatedAt.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", tag.CreatedAt.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if tag.LastSeen.Before(before) || tag.LastSeen.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", tag.LastSeen.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}

	time.Sleep(250 * time.Millisecond)
	dbents, err := c.db.FindEntitiesByContent(entity.Asset, before)
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	dbtags, err := c.db.GetEntityTags(dbent, before, tag.Property.Name())
	assert.NoError(t, err)
	if num := len(dbtags); num != 1 {
		t.Errorf("failed to return the corrent number of tags: %d", num)
	}
	dbtag := dbtags[0]

	if !reflect.DeepEqual(tag.Property, dbtag.Property) {
		t.Errorf("DeepEqual failed for the properties in the two tags")
	}
	if dbtag.CreatedAt.Before(before) || dbtag.CreatedAt.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", dbtag.CreatedAt.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if dbtag.LastSeen.Before(before) || dbtag.LastSeen.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", dbtag.LastSeen.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
}

func TestCreateEdgeProperty(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer c.Close()

	now := time.Now()
	before := now.Add(-2 * time.Second)
	edge, err := createTestEdge(c, now)
	assert.NoError(t, err)
	tag, err := c.CreateEdgeProperty(edge, &general.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foobar",
	})
	assert.NoError(t, err)
	after := time.Now().Add(250 * time.Millisecond)

	if tag.CreatedAt.Before(before) || tag.CreatedAt.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", tag.CreatedAt.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if tag.LastSeen.Before(before) || tag.LastSeen.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", tag.LastSeen.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}

	time.Sleep(250 * time.Millisecond)
	s, err := c.db.FindEntitiesByContent(edge.FromEntity.Asset, time.Time{})
	assert.NoError(t, err)

	o, err := c.db.FindEntitiesByContent(edge.ToEntity.Asset, time.Time{})
	assert.NoError(t, err)

	edges, err := c.db.OutgoingEdges(s[0], time.Time{}, edge.Relation.Label())
	assert.NoError(t, err)

	var target *types.Edge
	for _, e := range edges {
		if e.ToEntity.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge.Relation) {
			target = e
			break
		}
	}

	dbtags, err := c.db.GetEdgeTags(target, before, tag.Property.Name())
	assert.NoError(t, err)
	if num := len(dbtags); num != 1 {
		t.Errorf("failed to return the corrent number of tags: %d", num)
	}
	dbtag := dbtags[0]

	if !reflect.DeepEqual(tag.Property, dbtag.Property) {
		t.Errorf("DeepEqual failed for the properties in the two tags")
	}
	if dbtag.CreatedAt.Before(before) || dbtag.CreatedAt.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", dbtag.CreatedAt.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if dbtag.LastSeen.Before(before) || dbtag.LastSeen.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", dbtag.LastSeen.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
}

func TestFindEdgeTagById(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer c.Close()

	edge, err := createTestEdge(c, time.Now())
	assert.NoError(t, err)
	tag, err := c.CreateEdgeProperty(edge, &general.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foobar",
	})
	assert.NoError(t, err)

	tag2, err := c.FindEdgeTagById(tag.ID)
	assert.NoError(t, err)

	if !reflect.DeepEqual(tag.Property, tag2.Property) {
		t.Errorf("DeepEqual failed for the properties in the two tags")
	}
}

func TestFindEdgeTagsByContent(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer c.Close()

	// add some really old stuff to the database
	now := time.Now()
	ctime1 := now.Add(-24 * time.Hour)
	cbefore1 := ctime1.Add(-20 * time.Second)
	edge, err := createTestEdge(c, ctime1)
	assert.NoError(t, err)
	prop1 := &general.SimpleProperty{
		PropertyName:  "test1",
		PropertyValue: "foobar",
	}
	_, err = c.CreateEdgeTag(edge, &types.EdgeTag{
		CreatedAt: ctime1,
		LastSeen:  ctime1,
		Property:  prop1,
		Edge:      edge,
	})
	assert.NoError(t, err)
	// add some not so old stuff to the database
	ctime2 := now.Add(-8 * time.Hour)
	cbefore2 := ctime2.Add(-20 * time.Second)
	prop2 := &general.SimpleProperty{
		PropertyName:  "test2",
		PropertyValue: "foobar",
	}
	_, err = c.CreateEdgeTag(edge, &types.EdgeTag{
		CreatedAt: ctime2,
		LastSeen:  ctime2,
		Property:  prop2,
		Edge:      edge,
	})
	assert.NoError(t, err)
	// add new entities to the database
	prop3 := &general.SimpleProperty{
		PropertyName:  "test3",
		PropertyValue: "foobar",
	}
	_, err = c.CreateEdgeProperty(edge, prop3)
	assert.NoError(t, err)
	after := time.Now().Add(time.Second)

	_, err = c.FindEdgeTagsByContent(prop3, after)
	assert.Error(t, err)

	tags, err := c.FindEdgeTagsByContent(prop3, c.StartTime())
	assert.NoError(t, err)
	if len(tags) != 1 {
		t.Errorf("first request failed to produce the expected number of tags")
	}

	tags, err = c.FindEdgeTagsByContent(prop2, cbefore2)
	assert.NoError(t, err)
	if len(tags) != 1 {
		t.Errorf("second request failed to produce the expected number of tags")
	}

	tags, err = c.FindEdgeTagsByContent(prop1, cbefore1)
	assert.NoError(t, err)
	if len(tags) != 1 {
		t.Errorf("third request failed to produce the expected number of tags")
	}
}

func TestGetEdgeTags(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer c.Close()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	edge, err := createTestEdge(c, now)
	assert.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	s, err := c.db.FindEntitiesByContent(edge.FromEntity.Asset, time.Time{})
	assert.NoError(t, err)

	o, err := c.db.FindEntitiesByContent(edge.ToEntity.Asset, time.Time{})
	assert.NoError(t, err)

	edges, err := c.db.OutgoingEdges(s[0], time.Time{}, edge.Relation.Label())
	assert.NoError(t, err)

	var target *types.Edge
	for _, e := range edges {
		if e.ToEntity.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge.Relation) {
			target = e
			break
		}
	}
	time.Sleep(time.Second)

	set1 := stringset.New()
	defer set1.Close()
	// add some old stuff to the database
	for _, name := range []string{"owasp.org", "utica.edu", "sunypoly.edu"} {
		set1.Insert(name)
		_, err := c.db.CreateEdgeTag(target, &types.EdgeTag{
			CreatedAt: ctime,
			LastSeen:  ctime,
			Property: &general.SimpleProperty{
				PropertyName:  "test",
				PropertyValue: name,
			},
		})
		assert.NoError(t, err)
	}

	set2 := stringset.New()
	defer set2.Close()
	// add some new stuff to the database
	for _, name := range []string{"www.owasp.org", "www.utica.edu", "www.sunypoly.edu"} {
		set2.Insert(name)
		_, err := c.CreateEdgeProperty(edge, &general.SimpleProperty{
			PropertyName:  "test",
			PropertyValue: name,
		})
		assert.NoError(t, err)
	}
	time.Sleep(time.Second)
	after := time.Now()

	// some tests that shouldn't return anything
	_, err = c.GetEdgeTags(edge, after)
	assert.Error(t, err)
	// there shouldn't be a tag for this entity, since it didn't require the database
	_, err = c.cache.GetEdgeTags(edge, time.Time{}, "cache_get_edge_tags")
	assert.Error(t, err)

	tags, err := c.GetEdgeTags(edge, c.StartTime(), "test")
	assert.NoError(t, err)
	if num := len(tags); num != 3 {
		t.Errorf("incorrect number of edge tags: %d", num)
	}

	for _, tag := range tags {
		set2.Remove(tag.Property.Value())
	}
	// only entities from set2 should have been removed
	if set1.Len() != 3 || set2.Len() != 0 {
		t.Errorf("first request failed to produce the correct tags")
	}
	// there shouldn't be a tag for this entity, since it didn't require the database
	_, err = c.cache.GetEdgeTags(edge, time.Time{}, "cache_get_edge_tags")
	assert.Error(t, err)

	tags, err = c.GetEdgeTags(edge, before, "test")
	assert.NoError(t, err)
	if num := len(tags); num != 6 {
		t.Errorf("incorrect number of edge tags: %d", num)
	}

	for _, tag := range tags {
		set1.Remove(tag.Property.Value())
	}
	// all entities should now be been removed
	if set1.Len() != 0 || set2.Len() != 0 {
		t.Errorf("second request failed to produce the correct tags")
	}
	// there should be a tag for this entity
	tags, err = c.cache.GetEdgeTags(edge, time.Time{}, "cache_get_edge_tags")
	assert.NoError(t, err)
	if len(tags) != 1 {
		t.Errorf("second request failed to produce the expected number of edge tags")
	}

	tagtime, err := time.Parse(time.RFC3339Nano, tags[0].Property.Value())
	assert.NoError(t, err)
	if tagtime.Before(before) || tagtime.After(after) {
		t.Errorf("tag time: %s, before time: %s, after time: %s", tagtime.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
}

func TestDeleteEdgeTag(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, time.Minute)
	assert.NoError(t, err)
	defer c.Close()

	edge, err := createTestEdge(c, time.Now())
	assert.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	s, err := c.db.FindEntitiesByContent(edge.FromEntity.Asset, time.Time{})
	assert.NoError(t, err)

	o, err := c.db.FindEntitiesByContent(edge.ToEntity.Asset, time.Time{})
	assert.NoError(t, err)

	edges, err := c.db.OutgoingEdges(s[0], time.Time{}, edge.Relation.Label())
	assert.NoError(t, err)

	var target *types.Edge
	for _, e := range edges {
		if e.ToEntity.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge.Relation) {
			target = e
			break
		}
	}

	tag, err := c.CreateEdgeProperty(edge, &general.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foobar",
	})
	assert.NoError(t, err)
	time.Sleep(250 * time.Millisecond)

	err = c.DeleteEdgeTag(tag.ID)
	assert.NoError(t, err)
	time.Sleep(250 * time.Millisecond)

	_, err = c.FindEdgeTagById(tag.ID)
	assert.Error(t, err)

	_, err = c.db.GetEdgeTags(target, c.StartTime())
	assert.Error(t, err)
}
