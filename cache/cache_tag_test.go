// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"os"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/stretchr/testify/assert"
)

func TestCacheEntityTag(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		_ = db1.Close()
		_ = db2.Close()
		_ = os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, 2*time.Second)
	assert.NoError(t, err)
	defer func() { _ = c.Close() }()

	db2ent, err := db2.CreateEntity(&types.Entity{
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Asset:     &dns.FQDN{Name: "owasp.org"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, db2ent)

	tag, _, ok := c.checkCacheEntityTag(nil, "cache_create_entity")
	assert.Nil(t, tag)
	assert.False(t, ok)

	entity, err := c.CreateEntity(&types.Entity{
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Asset:     &dns.FQDN{Name: "owasp.org"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, entity)

	tag, _, ok = c.checkCacheEntityTag(entity, "cache_create_entity")
	assert.NotNil(t, tag)
	assert.False(t, ok)
	assert.Equal(t, db2ent.ID, tag.Property.Value())

	time.Sleep(3 * time.Second) // Ensure the tag is expired
	tag, _, ok = c.checkCacheEntityTag(entity, "cache_create_entity")
	assert.NotNil(t, tag)
	assert.True(t, ok)
	assert.Equal(t, db2ent.ID, tag.Property.Value())
}

func TestCacheEdgeTag(t *testing.T) {
	db1, db2, dir, err := createTestRepositories()
	assert.NoError(t, err)
	defer func() {
		_ = db1.Close()
		_ = db2.Close()
		_ = os.RemoveAll(dir)
	}()

	c, err := New(db1, db2, 2*time.Second)
	assert.NoError(t, err)
	defer func() { _ = c.Close() }()

	now := time.Now()
	db2ent1, err := db2.CreateEntity(&types.Entity{
		CreatedAt: now,
		LastSeen:  now,
		Asset:     &dns.FQDN{Name: "owasp.org"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, db2ent1)

	now = time.Now()
	db2ent2, err := db2.CreateEntity(&types.Entity{
		CreatedAt: now,
		LastSeen:  now,
		Asset:     &dns.FQDN{Name: "example.com"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, db2ent2)

	now = time.Now()
	db2edge, err := db2.CreateEdge(&types.Edge{
		CreatedAt: now,
		LastSeen:  now,
		Relation: &dns.BasicDNSRelation{
			Name: "dns_record",
			Header: dns.RRHeader{
				RRType: 5,
				Class:  1,
				TTL:    3600,
			},
		},
		FromEntity: db2ent2,
		ToEntity:   db2ent1,
	})

	tag, _, ok := c.checkCacheEdgeTag(nil, "cache_create_edge")
	assert.Nil(t, tag)
	assert.False(t, ok)

	now = time.Now()
	entity1, err := c.CreateEntity(&types.Entity{
		CreatedAt: now,
		LastSeen:  now,
		Asset:     &dns.FQDN{Name: "owasp.org"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, entity1)

	now = time.Now()
	entity2, err := c.CreateEntity(&types.Entity{
		CreatedAt: now,
		LastSeen:  now,
		Asset:     &dns.FQDN{Name: "example.com"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, entity2)

	now = time.Now()
	edge, err := c.CreateEdge(&types.Edge{
		CreatedAt: now,
		LastSeen:  now,
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
	assert.NoError(t, err)
	assert.NotNil(t, edge)

	tag, _, ok = c.checkCacheEdgeTag(edge, "cache_create_edge")
	assert.NotNil(t, tag)
	assert.False(t, ok)
	assert.Equal(t, db2edge.ID, tag.Property.Value())

	time.Sleep(3 * time.Second) // Ensure the tag is expired
	tag, _, ok = c.checkCacheEdgeTag(edge, "cache_create_edge")
	assert.NotNil(t, tag)
	assert.True(t, ok)
	assert.Equal(t, db2edge.ID, tag.Property.Value())
}
