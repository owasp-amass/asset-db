// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"time"

	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
)

type Cache struct {
	start time.Time
	freq  time.Duration
	cache repository.Repository
	db    repository.Repository
}

func New(cache, database repository.Repository, freq time.Duration) (*Cache, error) {
	return &Cache{
		start: time.Now(),
		freq:  freq,
		cache: cache,
		db:    database,
	}, nil
}

// StartTime returns the time that the cache was created.
func (c *Cache) StartTime() time.Time {
	return c.start
}

// Close implements the Repository interface.
func (c *Cache) Close() error {
	return c.cache.Close()
}

// GetDBType implements the Repository interface.
func (c *Cache) GetDBType() string {
	return c.db.GetDBType()
}

func (c *Cache) createCacheEntityTag(entity *types.Entity, name string, since time.Time) error {
	// remove all existing tags with the same name
	if tags, err := c.cache.GetEntityTags(entity, c.start, name); err == nil {
		for _, tag := range tags {
			_ = c.cache.DeleteEntityTag(tag.ID)
		}
	}

	_, err := c.cache.CreateEntityProperty(entity, &general.SimpleProperty{
		PropertyName:  name,
		PropertyValue: since.Format(time.RFC3339Nano),
	})
	return err
}

func (c *Cache) checkCacheEntityTag(entity *types.Entity, name string) (*types.EntityTag, time.Time, bool) {
	if tags, err := c.cache.GetEntityTags(entity, c.start, name); err == nil && len(tags) == 1 {
		if t, err := time.Parse(time.RFC3339Nano, tags[0].Property.Value()); err == nil {
			return tags[0], t, true
		}
	}
	return nil, time.Time{}, false
}

func (c *Cache) createCacheEdgeTag(edge *types.Edge, name string, since time.Time) error {
	// remove all existing tags with the same name
	if tags, err := c.cache.GetEdgeTags(edge, c.start, name); err == nil {
		for _, tag := range tags {
			_ = c.cache.DeleteEdgeTag(tag.ID)
		}
	}

	_, err := c.cache.CreateEdgeProperty(edge, &general.SimpleProperty{
		PropertyName:  name,
		PropertyValue: since.Format(time.RFC3339Nano),
	})
	return err
}

func (c *Cache) checkCacheEdgeTag(edge *types.Edge, name string) (*types.EdgeTag, time.Time, bool) {
	if tags, err := c.cache.GetEdgeTags(edge, c.start, name); err == nil && len(tags) == 1 {
		if t, err := time.Parse(time.RFC3339Nano, tags[0].Property.Value()); err == nil {
			return tags[0], t, true
		}
	}
	return nil, time.Time{}, false
}
