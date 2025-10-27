// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
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

func TestCreateEntityTag(t *testing.T) {
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
	ctx := context.Background()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	after := ctime.Add(2 * time.Second)
	entity, err := c.CreateAsset(ctx, &dns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)
	tag, err := c.CreateEntityTag(ctx, entity, &types.EntityTag{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Property: &general.SimpleProperty{
			PropertyName:  "test",
			PropertyValue: "foobar",
		},
		Entity: entity,
	})
	assert.NoError(t, err)
	assert.WithinRange(t, tag.CreatedAt, before, after)
	assert.WithinRange(t, tag.LastSeen, before, after)

	time.Sleep(250 * time.Millisecond)
	dbents, err := c.db.FindEntitiesByContent(ctx, "fqdn", before, types.ContentFilters{
		"name": "owasp.org",
	})
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	dbtags, err := c.db.FindEntityTags(ctx, dbent, before, tag.Property.Name())
	assert.NoError(t, err)
	if num := len(dbtags); num != 1 {
		t.Errorf("failed to return the corrent number of tags: %d", num)
	}
	dbtag := dbtags[0]

	if !reflect.DeepEqual(tag.Property, dbtag.Property) {
		t.Errorf("DeepEqual failed for the properties in the two tags")
	}
	assert.WithinRange(t, dbtag.CreatedAt, before, after)
	assert.WithinRange(t, dbtag.LastSeen, before, after)
}

func TestCreateEntityProperty(t *testing.T) {
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
	ctx := context.Background()
	before := now.Add(-2 * time.Second)
	entity, err := c.CreateAsset(ctx, &dns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)
	tag, err := c.CreateEntityProperty(ctx, entity, &general.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foobar",
	})
	assert.NoError(t, err)
	after := time.Now().Add(250 * time.Millisecond)
	assert.WithinRange(t, tag.CreatedAt, before, after)
	assert.WithinRange(t, tag.LastSeen, before, after)

	time.Sleep(250 * time.Millisecond)
	dbents, err := c.db.FindEntitiesByContent(ctx, "fqdn", before, types.ContentFilters{
		"name": "owasp.org",
	})
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	dbtags, err := c.db.FindEntityTags(ctx, dbent, before, tag.Property.Name())
	assert.NoError(t, err)
	if num := len(dbtags); num != 1 {
		t.Errorf("failed to return the corrent number of tags: %d", num)
	}
	dbtag := dbtags[0]

	if !reflect.DeepEqual(tag.Property, dbtag.Property) {
		t.Errorf("DeepEqual failed for the properties in the two tags")
	}
	assert.WithinRange(t, dbtag.CreatedAt, before, after)
	assert.WithinRange(t, dbtag.LastSeen, before, after)
}

func TestFindEntityTagById(t *testing.T) {
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

	ctx := context.Background()
	entity, err := c.CreateAsset(ctx, &dns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)
	tag, err := c.CreateEntityProperty(ctx, entity, &general.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foobar",
	})
	assert.NoError(t, err)

	tag2, err := c.FindEntityTagById(ctx, tag.ID)
	assert.NoError(t, err)

	if !reflect.DeepEqual(tag.Property, tag2.Property) {
		t.Errorf("DeepEqual failed for the properties in the two tags")
	}
}

func TestFindEntityTagsByContent(t *testing.T) {
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

	// add some really old stuff to the database
	now := time.Now()
	prop := &general.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foobar",
	}

	ctx := context.Background()
	ctime1 := now.Add(-24 * time.Hour)
	fqdn1 := &dns.FQDN{Name: "owasp.org"}
	entity1, err := c.db.CreateEntity(ctx, &types.Entity{
		CreatedAt: ctime1,
		LastSeen:  ctime1,
		Asset:     fqdn1,
	})
	assert.NoError(t, err)
	_, err = c.db.CreateEntityTag(ctx, entity1, &types.EntityTag{
		CreatedAt: ctime1,
		LastSeen:  ctime1,
		Property:  prop,
	})
	assert.NoError(t, err)
	// add some not so old stuff to the database
	ctime2 := now.Add(-8 * time.Hour)
	fqdn2 := &dns.FQDN{Name: "utica.edu"}
	entity2, err := c.db.CreateEntity(ctx, &types.Entity{
		CreatedAt: ctime2,
		LastSeen:  ctime2,
		Asset:     fqdn2,
	})
	assert.NoError(t, err)
	_, err = c.db.CreateEntityTag(ctx, entity2, &types.EntityTag{
		CreatedAt: ctime2,
		LastSeen:  ctime2,
		Property:  prop,
	})
	assert.NoError(t, err)
	// add new entities to the database
	entity3, err := c.CreateAsset(ctx, &dns.FQDN{Name: "sunypoly.edu"})
	assert.NoError(t, err)
	_, err = c.CreateEntityProperty(ctx, entity3, prop)
	assert.NoError(t, err)
}

func TestGetEntityTags(t *testing.T) {
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
	ctx := context.Background()
	ctime := now.Add(-8 * time.Hour)
	before := ctime.Add(-2 * time.Second)
	entity, err := c.CreateEntity(ctx, &types.Entity{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Asset:     &dns.FQDN{Name: "caffix.com"},
	})
	assert.NoError(t, err)
	time.Sleep(250 * time.Millisecond)

	dbents, err := c.db.FindEntitiesByContent(ctx, "fqdn", time.Time{}, types.ContentFilters{
		"name": "caffix.com",
	})
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]
	time.Sleep(time.Second)

	set1 := stringset.New()
	defer set1.Close()
	// add some old stuff to the database
	for _, name := range []string{"owasp.org", "utica.edu", "sunypoly.edu"} {
		set1.Insert(name)
		_, err := c.db.CreateEntityTag(ctx, dbent, &types.EntityTag{
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
		_, err := c.CreateEntityProperty(ctx, entity, &general.SimpleProperty{
			PropertyName:  "test",
			PropertyValue: name,
		})
		assert.NoError(t, err)
	}
	time.Sleep(time.Second)
	after := time.Now()

	// some tests that shouldn't return anything
	_, err = c.FindEntityTags(ctx, entity, after)
	assert.Error(t, err)
	// there shouldn't be a tag for this entity, since it didn't require the database
	_, err = c.cache.FindEntityTags(ctx, entity, time.Time{}, "cache_get_entity_tags")
	assert.Error(t, err)

	tags, err := c.FindEntityTags(ctx, entity, c.StartTime(), "test")
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
	// there shouldn't be a tag for this entity, since it didn't require the database
	_, err = c.cache.FindEntityTags(ctx, entity, time.Time{}, "cache_get_entity_tags")
	assert.Error(t, err)

	tags, err = c.FindEntityTags(ctx, entity, before, "test")
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
	// there should be a tag for this entity
	tags, err = c.cache.FindEntityTags(ctx, entity, time.Time{}, "cache_get_entity_tags")
	assert.NoError(t, err)
	if len(tags) != 1 {
		t.Errorf("second request failed to produce the expected number of edge tags")
	}
	ts := tags[0].Property.(*types.CacheProperty).Timestamp

	tagtime, err := time.Parse(time.RFC3339Nano, ts)
	assert.NoError(t, err)
	assert.WithinRange(t, tagtime, before, after)
}

func TestDeleteEntityTag(t *testing.T) {
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

	ctx := context.Background()
	entity, err := c.CreateAsset(ctx, &dns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	dbents, err := c.db.FindEntitiesByContent(ctx, "fqdn", time.Time{}, types.ContentFilters{
		"name": "owasp.org",
	})
	assert.NoError(t, err)
	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	tag, err := c.CreateEntityProperty(ctx, entity, &general.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foobar",
	})
	assert.NoError(t, err)
	time.Sleep(250 * time.Millisecond)

	err = c.DeleteEntityTag(ctx, tag.ID)
	assert.NoError(t, err)
	time.Sleep(250 * time.Millisecond)

	_, err = c.FindEntityTagById(ctx, tag.ID)
	assert.Error(t, err)

	tags, err := c.db.FindEntityTags(ctx, dbent, c.StartTime())
	assert.Error(t, err)
	if len(tags) > 0 {
		for _, tag := range tags {
			t.Errorf("tag %s:%s should have been deleted", tag.Property.Name(), tag.Property.Value())
		}
	}
}
