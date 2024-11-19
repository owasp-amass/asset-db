// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/stretchr/testify/assert"
)

func TestCreateEntity(t *testing.T) {
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
	entity, err := c.CreateEntity(&types.Entity{
		CreatedAt: ctime,
		LastSeen:  ctime,
		Asset:     &domain.FQDN{Name: "owasp.org"},
	})
	assert.NoError(t, err)

	if entity.CreatedAt.Before(before) || entity.CreatedAt.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", entity.CreatedAt.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if entity.LastSeen.Before(before) || entity.LastSeen.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", entity.LastSeen.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if tags, err := c.cache.GetEntityTags(entity, now, "cache_create_entity"); err != nil || len(tags) != 1 {
		t.Errorf("failed to create the cache tag:")
	}

	time.Sleep(time.Second)
	dbents, err := db2.FindEntityByContent(entity.Asset, before)
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	if !reflect.DeepEqual(entity.Asset, dbent.Asset) {
		t.Errorf("DeepEqual failed for the assets in the two entities")
	}
	if dbent.CreatedAt.Before(before) || dbent.CreatedAt.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", dbent.CreatedAt.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if dbent.LastSeen.Before(before) || dbent.LastSeen.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", dbent.LastSeen.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
}

func TestCreateAsset(t *testing.T) {
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
	after := now.Add(2 * time.Second)
	entity, err := c.CreateAsset(&domain.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)

	if entity.CreatedAt.Before(before) || entity.CreatedAt.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", entity.CreatedAt.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if entity.LastSeen.Before(before) || entity.LastSeen.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", entity.LastSeen.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if tags, err := c.cache.GetEntityTags(entity, now, "cache_create_asset"); err != nil || len(tags) != 1 {
		t.Errorf("failed to create the cache tag:")
	}

	time.Sleep(time.Second)
	dbents, err := db2.FindEntityByContent(entity.Asset, now)
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	if !reflect.DeepEqual(entity.Asset, dbent.Asset) {
		t.Errorf("DeepEqual failed for the assets in the two entities")
	}
	if dbent.CreatedAt.Before(before) || dbent.CreatedAt.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", dbent.CreatedAt.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if dbent.LastSeen.Before(before) || dbent.LastSeen.After(after) {
		t.Errorf("create time: %s, before time: %s, after time: %s", dbent.LastSeen.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
}

func TestFindEntityById(t *testing.T) {
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

	entity1, err := c.CreateAsset(&domain.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)

	entity2, err := c.FindEntityById(entity1.ID)
	assert.NoError(t, err)

	if !reflect.DeepEqual(entity1.Asset, entity2.Asset) {
		t.Errorf("DeepEqual failed for the assets in the two entities")
	}
}

func TestDeleteEntity(t *testing.T) {
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

	err = c.DeleteEntity(entity.ID)
	assert.NoError(t, err)

	_, err = c.FindEntityById(entity.ID)
	assert.Error(t, err)

	time.Sleep(250 * time.Millisecond)
	_, err = db2.FindEntityByContent(entity.Asset, time.Time{})
	assert.Error(t, err)
}
