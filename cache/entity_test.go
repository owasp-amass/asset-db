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
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/stretchr/testify/assert"
)

func TestCreateEntity(t *testing.T) {
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
	entity, err := c.CreateEntity(ctx, &types.Entity{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Asset:     &dns.FQDN{Name: "owasp.org"},
	})
	assert.NoError(t, err)
	assert.WithinRange(t, entity.CreatedAt, before, after)
	assert.WithinRange(t, entity.LastSeen, before, after)

	if tags, err := c.cache.FindEntityTags(ctx, entity, now, "cache_create_entity"); err != nil || len(tags) != 1 {
		t.Errorf("failed to create the cache tag:")
	}

	time.Sleep(250 * time.Millisecond)
	dbents, err := db2.FindEntitiesByContent(ctx, string(entity.Asset.AssetType()), before, types.ContentFilters{
		"name": "owasp.org",
	})
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	if !reflect.DeepEqual(entity.Asset, dbent.Asset) {
		t.Errorf("DeepEqual failed for the assets in the two entities")
	}
	assert.WithinRange(t, dbent.CreatedAt, before, after)
	assert.WithinRange(t, dbent.LastSeen, before, after)
}

func TestCreateAsset(t *testing.T) {
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
	after := now.Add(2 * time.Second)
	entity, err := c.CreateAsset(ctx, &dns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)
	assert.WithinRange(t, entity.CreatedAt, before, after)
	assert.WithinRange(t, entity.LastSeen, before, after)

	if tags, err := c.cache.FindEntityTags(ctx, entity, now, "cache_create_entity"); err != nil || len(tags) != 1 {
		t.Errorf("failed to create the cache tag:")
	}

	time.Sleep(250 * time.Millisecond)
	dbents, err := db2.FindEntitiesByContent(ctx, string(entity.Asset.AssetType()), now, types.ContentFilters{
		"name": "owasp.org",
	})
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	if !reflect.DeepEqual(entity.Asset, dbent.Asset) {
		t.Errorf("DeepEqual failed for the assets in the two entities")
	}
	assert.WithinRange(t, dbent.CreatedAt, before, after)
	assert.WithinRange(t, dbent.LastSeen, before, after)
}

func TestFindEntityById(t *testing.T) {
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
	entity1, err := c.CreateAsset(ctx, &dns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)

	entity2, err := c.FindEntityById(ctx, entity1.ID)
	assert.NoError(t, err)

	if !reflect.DeepEqual(entity1.Asset, entity2.Asset) {
		t.Errorf("DeepEqual failed for the assets in the two entities")
	}
}

func TestFindEntityByContent(t *testing.T) {
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
	ctx := context.Background()
	ctime1 := now.Add(-24 * time.Hour)
	cbefore1 := ctime1.Add(-20 * time.Second)
	fqdn1 := &dns.FQDN{Name: "owasp.org"}
	entity1, err := c.db.CreateEntity(ctx, &types.Entity{
		CreatedAt: ctime1,
		LastSeen:  ctime1,
		Asset:     fqdn1,
	})
	assert.NoError(t, err)
	// add some not so old stuff to the database
	ctime2 := now.Add(-8 * time.Hour)
	cbefore2 := ctime2.Add(-20 * time.Second)
	fqdn2 := &dns.FQDN{Name: "utica.edu"}
	entity2, err := c.db.CreateEntity(ctx, &types.Entity{
		CreatedAt: ctime2,
		LastSeen:  ctime2,
		Asset:     fqdn2,
	})
	assert.NoError(t, err)
	// add new entities to the database
	fqdn3 := &dns.FQDN{Name: "sunypoly.edu"}
	entity3, err := c.CreateEntity(ctx, &types.Entity{
		CreatedAt: now,
		LastSeen:  now,
		Asset:     fqdn3,
	})
	assert.NoError(t, err)
	after := time.Now().Add(2 * time.Second)

	_, err = c.FindEntitiesByContent(ctx, "fqdn", after, types.ContentFilters{
		"name": "sunypoly.edu",
	})
	assert.Error(t, err)

	entities, err := c.FindEntitiesByContent(ctx, "fqdn", now, types.ContentFilters{
		"name": "sunypoly.edu",
	})
	assert.NoError(t, err)
	if len(entities) != 1 {
		t.Errorf("first request failed to produce the expected number of entities")
	}

	e := entities[0]
	if !reflect.DeepEqual(e.Asset, entity3.Asset) {
		t.Errorf("DeepEqual failed for the assets in the two entities")
	}

	_, err = c.FindEntitiesByContent(ctx, "fqdn", c.StartTime(), types.ContentFilters{
		"name": "utica.edu",
	})
	assert.Error(t, err)

	entities, err = c.FindEntitiesByContent(ctx, "fqdn", cbefore2, types.ContentFilters{
		"name": "utica.edu",
	})
	assert.NoError(t, err)
	if len(entities) != 1 {
		t.Errorf("second request failed to produce the expected number of entities")
	}

	e = entities[0]
	if !reflect.DeepEqual(e.Asset, entity2.Asset) {
		t.Errorf("DeepEqual failed for the assets in the two entities")
	}

	_, err = c.FindEntitiesByContent(ctx, "fqdn", cbefore2, types.ContentFilters{
		"name": "owasp.org",
	})
	assert.Error(t, err)

	entities, err = c.FindEntitiesByContent(ctx, "fqdn", cbefore1, types.ContentFilters{
		"name": "owasp.org",
	})
	assert.NoError(t, err)
	if len(entities) != 1 {
		t.Errorf("third request failed to produce the expected number of entities")
	}

	e = entities[0]
	if !reflect.DeepEqual(e.Asset, entity1.Asset) {
		t.Errorf("DeepEqual failed for the assets in the two entities")
	}
}

func TestFindEntitiesByType(t *testing.T) {
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

	set1 := stringset.New()
	defer set1.Close()
	// add some really old stuff to the database
	now := time.Now()
	ctx := context.Background()
	ctime1 := now.Add(-24 * time.Hour)
	cbefore1 := ctime1.Add(-20 * time.Second)
	cafter1 := ctime1.Add(20 * time.Second)
	for _, name := range []string{"owasp.org", "utica.edu", "sunypoly.edu"} {
		set1.Insert(name)
		_, err := c.db.CreateEntity(ctx, &types.Entity{
			CreatedAt: ctime1,
			LastSeen:  ctime1,
			Asset:     &dns.FQDN{Name: name},
		})
		assert.NoError(t, err)
	}

	set2 := stringset.New()
	defer set2.Close()
	// add some not so old stuff to the database
	ctime2 := now.Add(-8 * time.Hour)
	cbefore2 := ctime2.Add(-20 * time.Second)
	cafter2 := ctime2.Add(20 * time.Second)
	for _, name := range []string{"www.owasp.org", "www.utica.edu", "www.sunypoly.edu"} {
		set2.Insert(name)
		_, err := c.db.CreateEntity(ctx, &types.Entity{
			CreatedAt: ctime2,
			LastSeen:  ctime2,
			Asset:     &dns.FQDN{Name: name},
		})
		assert.NoError(t, err)
	}

	set3 := stringset.New()
	defer set3.Close()
	// add new entities to the database
	after := now.Add(20 * time.Second)
	for _, name := range []string{"ns1.owasp.org", "ns1.utica.edu", "ns1.sunypoly.edu"} {
		set3.Insert(name)
		_, err := c.CreateAsset(ctx, &dns.FQDN{Name: name})
		assert.NoError(t, err)
	}

	// no results should be produced with this since param
	_, err = c.FindEntitiesByType(ctx, oam.FQDN, after)
	assert.Error(t, err)

	entities, err := c.FindEntitiesByType(ctx, oam.FQDN, c.StartTime())
	assert.NoError(t, err)
	if len(entities) != 3 {
		t.Errorf("first request failed to produce the expected number of entities")
	}

	for _, entity := range entities {
		if fqdn, ok := entity.Asset.(*dns.FQDN); ok {
			set1.Remove(fqdn.Name)
			set2.Remove(fqdn.Name)
			set3.Remove(fqdn.Name)
		}
	}

	// only entities from set3 should have been removed
	if set1.Len() != 3 || set2.Len() != 3 || set3.Len() != 0 {
		t.Errorf("first request failed to produce the correct entities")
	}
	// there shouldn't be a tag for this entity, since it didn't require the database
	_, err = c.cache.FindEntityTags(ctx, entities[0], now, "cache_find_entities_by_type")
	assert.Error(t, err)

	entities, err = c.FindEntitiesByType(ctx, oam.FQDN, ctime2)
	assert.NoError(t, err)
	if len(entities) != 6 {
		t.Errorf("second request failed to produce the expected number of entities")
	}

	for _, entity := range entities {
		if fqdn, ok := entity.Asset.(*dns.FQDN); ok {
			set1.Remove(fqdn.Name)
			set2.Remove(fqdn.Name)
			set3.Remove(fqdn.Name)
		}
	}

	// only entities from set3 should have been removed
	if set1.Len() != 3 || set2.Len() != 0 || set3.Len() != 0 {
		t.Errorf("second request failed to produce the correct entities")
	}
	// there should be a tag for this entity
	tags, err := c.cache.FindEntityTags(ctx, entities[0], time.Time{}, "cache_find_entities_by_type")
	assert.NoError(t, err)
	if len(tags) != 1 {
		t.Errorf("second request failed to produce the expected number of entity tags")
	}
	ts := tags[0].Property.(*types.CacheProperty).Timestamp

	tagtime, err := time.Parse(time.RFC3339Nano, ts)
	assert.NoError(t, err)
	assert.WithinRange(t, tagtime, cbefore2, cafter2)

	entities, err = c.FindEntitiesByType(ctx, oam.FQDN, ctime1)
	assert.NoError(t, err)
	if len(entities) != 9 {
		t.Errorf("third request failed to produce the expected number of entities")
	}

	for _, entity := range entities {
		if fqdn, ok := entity.Asset.(*dns.FQDN); ok {
			set1.Remove(fqdn.Name)
			set2.Remove(fqdn.Name)
			set3.Remove(fqdn.Name)
		}
	}

	// only entities from set3 should have been removed
	if set1.Len() != 0 || set2.Len() != 0 || set3.Len() != 0 {
		t.Errorf("third request failed to produce the correct entities")
	}
	// there should now be a new tag for this entity
	tags, err = c.cache.FindEntityTags(ctx, entities[0], time.Time{}, "cache_find_entities_by_type")
	assert.NoError(t, err)
	if len(tags) != 1 {
		t.Errorf("third request failed to produce the expected number of entity tags")
	}
	ts = tags[0].Property.(*types.CacheProperty).Timestamp

	tagtime, err = time.Parse(time.RFC3339Nano, ts)
	assert.NoError(t, err)
	assert.WithinRange(t, tagtime, cbefore1, cafter1)
}

func TestDeleteEntity(t *testing.T) {
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

	err = c.DeleteEntity(ctx, entity.ID)
	assert.NoError(t, err)

	_, err = c.FindEntityById(ctx, entity.ID)
	assert.Error(t, err)

	time.Sleep(250 * time.Millisecond)
	_, err = db2.FindEntitiesByContent(ctx, "fqdn", time.Time{}, types.ContentFilters{
		"name": "owasp.org",
	})
	assert.Error(t, err)
}
