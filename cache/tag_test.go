// Copyright © by Jeff Foley 2017-2024. All rights reserved.
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
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/property"
	"github.com/stretchr/testify/assert"
)

func TestCreateEntityTag(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2)
	assert.NoError(t, err)
	defer c.Close()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	after := ctime.Add(2 * time.Second)
	entity, err := c.CreateAsset(&domain.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)
	tag, err := c.CreateEntityTag(entity, &types.EntityTag{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Property: &property.SimpleProperty{
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
	dbents, err := c.db.FindEntityByContent(entity.Asset, before)
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

func TestCreateEntityProperty(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2)
	assert.NoError(t, err)
	defer c.Close()

	now := time.Now()
	before := now.Add(-2 * time.Second)
	entity, err := c.CreateAsset(&domain.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)
	tag, err := c.CreateEntityProperty(entity, &property.SimpleProperty{
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
	dbents, err := c.db.FindEntityByContent(entity.Asset, before)
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

func TestFindEntityTagById(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2)
	assert.NoError(t, err)
	defer c.Close()

	entity, err := c.CreateAsset(&domain.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)
	tag, err := c.CreateEntityProperty(entity, &property.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foobar",
	})
	assert.NoError(t, err)

	tag2, err := c.FindEntityTagById(tag.ID)
	assert.NoError(t, err)

	if !reflect.DeepEqual(tag.Property, tag2.Property) {
		t.Errorf("DeepEqual failed for the properties in the two tags")
	}
}

func TestGetEntityTags(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2)
	assert.NoError(t, err)
	defer c.Close()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	entity, err := c.CreateEntity(&types.Entity{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Asset:     &domain.FQDN{Name: "caffix.com"},
	})
	assert.NoError(t, err)
	time.Sleep(250 * time.Millisecond)

	dbents, err := c.db.FindEntityByContent(entity.Asset, time.Time{})
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	set1 := stringset.New()
	defer set1.Close()
	// add some old stuff to the database
	for _, name := range []string{"owasp.org", "utica.edu", "sunypoly.edu"} {
		set1.Insert(name)
		_, err := c.db.CreateEntityTag(dbent, &types.EntityTag{
			CreatedAt: ctime,
			LastSeen:  ctime,
			Property: &property.SimpleProperty{
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
		_, err := c.CreateEntityProperty(entity, &property.SimpleProperty{
			PropertyName:  "test",
			PropertyValue: name,
		})
		assert.NoError(t, err)
	}
	after := time.Now()

	// some tests that shouldn't return anything
	_, err = c.GetEntityTags(entity, after)
	assert.Error(t, err)

	tags, err := c.GetEntityTags(entity, now, "test")
	assert.NoError(t, err)
	if num := len(tags); num != 3 {
		t.Errorf("incorrect number of entity tags: %d", num)
	}

	for _, tag := range tags {
		set2.Remove(tag.Property.Value())
	}
	// only entities from set2 should have been removed
	if set1.Len() != 3 || set2.Len() != 0 {
		t.Errorf("first request failed to produce the correct tags")
	}

	tags, err = c.GetEntityTags(entity, before, "test")
	assert.NoError(t, err)
	if num := len(tags); num != 6 {
		t.Errorf("incorrect number of entity tags: %d", num)
	}

	for _, tag := range tags {
		set1.Remove(tag.Property.Value())
	}
	// all entities should now be been removed
	if set1.Len() != 0 || set2.Len() != 0 {
		t.Errorf("second request failed to produce the correct tags")
	}
}

func TestDeleteEntityTag(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2)
	assert.NoError(t, err)
	defer c.Close()

	entity, err := c.CreateAsset(&domain.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	dbents, err := c.db.FindEntityByContent(entity.Asset, time.Time{})
	assert.NoError(t, err)
	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	tag, err := c.CreateEntityProperty(entity, &property.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foobar",
	})
	assert.NoError(t, err)
	time.Sleep(250 * time.Millisecond)

	err = c.DeleteEntityTag(tag.ID)
	assert.NoError(t, err)
	time.Sleep(250 * time.Millisecond)

	_, err = c.FindEntityTagById(tag.ID)
	assert.Error(t, err)

	tags, err := c.db.GetEntityTags(dbent, c.StartTime())
	assert.Error(t, err)
	if len(tags) > 0 {
		for _, tag := range tags {
			t.Errorf("tag %s:%s should have been deleted", tag.Property.Name(), tag.Property.Value())
		}
	}
}

func TestCreateEdgeTag(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2)
	assert.NoError(t, err)
	defer c.Close()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	after := ctime.Add(2 * time.Second)
	entity, err := c.CreateAsset(&domain.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)
	tag, err := c.CreateEntityTag(entity, &types.EntityTag{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Property: &property.SimpleProperty{
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
	dbents, err := c.db.FindEntityByContent(entity.Asset, before)
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

	c, err := New(db1, db2)
	assert.NoError(t, err)
	defer c.Close()

	now := time.Now()
	before := now.Add(-2 * time.Second)
	edge, err := createTestEdge(c, now)
	assert.NoError(t, err)
	tag, err := c.CreateEdgeProperty(edge, &property.SimpleProperty{
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
	s, err := c.db.FindEntityByContent(edge.FromEntity.Asset, time.Time{})
	assert.NoError(t, err)

	o, err := c.db.FindEntityByContent(edge.ToEntity.Asset, time.Time{})
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

	c, err := New(db1, db2)
	assert.NoError(t, err)
	defer c.Close()

	edge, err := createTestEdge(c, time.Now())
	assert.NoError(t, err)
	tag, err := c.CreateEdgeProperty(edge, &property.SimpleProperty{
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

func TestGetEdgeTags(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2)
	assert.NoError(t, err)
	defer c.Close()

	now := time.Now()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	edge, err := createTestEdge(c, now)
	assert.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	s, err := c.db.FindEntityByContent(edge.FromEntity.Asset, time.Time{})
	assert.NoError(t, err)

	o, err := c.db.FindEntityByContent(edge.ToEntity.Asset, time.Time{})
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

	set1 := stringset.New()
	defer set1.Close()
	// add some old stuff to the database
	for _, name := range []string{"owasp.org", "utica.edu", "sunypoly.edu"} {
		set1.Insert(name)
		_, err := c.db.CreateEdgeTag(target, &types.EdgeTag{
			CreatedAt: ctime,
			LastSeen:  ctime,
			Property: &property.SimpleProperty{
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
		_, err := c.CreateEdgeProperty(edge, &property.SimpleProperty{
			PropertyName:  "test",
			PropertyValue: name,
		})
		assert.NoError(t, err)
	}
	after := time.Now().Add(time.Second)

	// some tests that shouldn't return anything
	_, err = c.GetEdgeTags(edge, after)
	assert.Error(t, err)

	tags, err := c.GetEdgeTags(edge, now, "test")
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
}

func TestDeleteEdgeTag(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		db1.Close()
		db2.Close()
		os.RemoveAll(dir)
	}()

	c, err := New(db1, db2)
	assert.NoError(t, err)
	defer c.Close()

	edge, err := createTestEdge(c, time.Now())
	assert.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	s, err := c.db.FindEntityByContent(edge.FromEntity.Asset, time.Time{})
	assert.NoError(t, err)

	o, err := c.db.FindEntityByContent(edge.ToEntity.Asset, time.Time{})
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

	tag, err := c.CreateEdgeProperty(edge, &property.SimpleProperty{
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
