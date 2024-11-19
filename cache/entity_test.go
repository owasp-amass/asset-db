// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"reflect"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/stretchr/testify/assert"
)

func TestCreateEntity(t *testing.T) {
	cache, database, err := createTestRepositories()
	assert.NoError(t, err)
	defer cache.Close()
	defer database.Close()
	defer teardownPostgres()

	c, err := New(cache, database)
	assert.NoError(t, err)
	defer c.Close()

	now := time.Now()
	t1 := now.Add(-1 * time.Second)
	entity, err := c.CreateEntity(&types.Entity{
		CreatedAt: now,
		LastSeen:  now,
		Asset:     &domain.FQDN{Name: "owasp.org"},
	})
	t2 := time.Now().Add(time.Second)
	assert.NoError(t, err)

	if entity.CreatedAt.Before(t1) || entity.CreatedAt.After(t2) {
		t.Errorf("create time: %s, t1 time: %s, t2 time: %s", entity.CreatedAt.Format(time.RFC3339Nano), t1.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano))
	}
	if entity.LastSeen.Before(t1) || entity.LastSeen.After(t2) {
		t.Errorf("create time: %s, t1 time: %s, t2 time: %s", entity.LastSeen.Format(time.RFC3339Nano), t1.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano))
	}

	time.Sleep(time.Second)
	t2 = time.Now().Add(time.Second)
	dbents, err := database.FindEntityByContent(entity.Asset, time.Time{})
	assert.NoError(t, err)

	if num := len(dbents); num != 1 {
		t.Errorf("failed to return the corrent number of entities: %d", num)
	}
	dbent := dbents[0]

	if !reflect.DeepEqual(entity.Asset, dbent.Asset) {
		t.Errorf("DeepEqual failed for the assets in the two entities")
	}
	if dbent.CreatedAt.Before(t1) || dbent.CreatedAt.After(t2) {
		t.Errorf("create time: %s, t1 time: %s, t2 time: %s", dbent.CreatedAt.Format(time.RFC3339Nano), t1.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano))
	}
	if dbent.LastSeen.Before(t1) || dbent.LastSeen.After(t2) {
		t.Errorf("create time: %s, t1 time: %s, t2 time: %s", dbent.LastSeen.Format(time.RFC3339Nano), t1.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano))
	}
}
