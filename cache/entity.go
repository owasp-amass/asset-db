// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// CreateEntity implements the Repository interface.
func (c *Cache) CreateEntity(input *types.Entity) (*types.Entity, error) {
	c.Lock()
	defer c.Unlock()

	entity, err := c.cache.CreateEntity(input)
	if err != nil {
		return nil, err
	}

	if _, _, found := c.checkCacheEntityTag(entity, "cache_create_entity"); !found {
		_ = c.createCacheEntityTag(entity, "cache_create_entity", time.Now())

		c.appendToDBQueue(func() {
			_, _ = c.db.CreateEntity(&types.Entity{
				CreatedAt: input.CreatedAt,
				LastSeen:  input.LastSeen,
				Asset:     input.Asset,
			})
		})
	}

	return entity, nil
}

// CreateAsset implements the Repository interface.
func (c *Cache) CreateAsset(asset oam.Asset) (*types.Entity, error) {
	c.Lock()
	defer c.Unlock()

	entity, err := c.cache.CreateAsset(asset)
	if err != nil {
		return nil, err
	}

	if _, _, found := c.checkCacheEntityTag(entity, "cache_create_asset"); !found {
		_ = c.createCacheEntityTag(entity, "cache_create_asset", time.Now())

		c.appendToDBQueue(func() {
			_, _ = c.db.CreateAsset(asset)
		})
	}

	return entity, nil
}

// FindEntityById implements the Repository interface.
func (c *Cache) FindEntityById(id string) (*types.Entity, error) {
	c.Lock()
	defer c.Unlock()

	return c.cache.FindEntityById(id)
}

// FindEntityByContent implements the Repository interface.
func (c *Cache) FindEntityByContent(asset oam.Asset, since time.Time) ([]*types.Entity, error) {
	c.Lock()
	entities, err := c.cache.FindEntityByContent(asset, since)
	if err == nil && len(entities) == 1 {
		if !since.IsZero() && !since.Before(c.start) {
			c.Unlock()
			return entities, err
		}
		if _, last, found := c.checkCacheEntityTag(entities[0], "cache_find_entity_by_content"); found && !since.Before(last) {
			c.Unlock()
			return entities, err
		}
	}
	c.Unlock()

	var dberr error
	var dbentities []*types.Entity
	done := make(chan struct{}, 1)
	c.appendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		dbentities, dberr = c.db.FindEntityByContent(asset, since)
	})
	<-done
	close(done)

	if dberr != nil {
		return entities, err
	}

	c.Lock()
	defer c.Unlock()

	var results []*types.Entity
	for _, entity := range dbentities {
		if e, err := c.cache.CreateEntity(&types.Entity{
			CreatedAt: entity.CreatedAt,
			LastSeen:  entity.LastSeen,
			Asset:     entity.Asset,
		}); err == nil {
			results = append(results, e)
			if tags, err := c.cache.GetEntityTags(entity, c.start, "cache_find_entity_by_content"); err == nil && len(tags) > 0 {
				for _, tag := range tags {
					_ = c.cache.DeleteEntityTag(tag.ID)
				}
			}
			_ = c.createCacheEntityTag(entity, "cache_find_entity_by_content", since)
		}
	}
	return results, nil
}

// FindEntitiesByType implements the Repository interface.
func (c *Cache) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	c.Lock()
	entities, err := c.cache.FindEntitiesByType(atype, since)
	if err == nil && len(entities) > 0 {
		if !since.IsZero() && !since.Before(c.start) {
			c.Unlock()
			return entities, err
		}
		if _, last, found := c.checkCacheEntityTag(entities[0], "cache_find_entities_by_type"); found && !since.Before(last) {
			c.Unlock()
			return entities, err
		}
	}
	c.Unlock()

	var dberr error
	var dbentities []*types.Entity
	done := make(chan struct{}, 1)
	c.appendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		dbentities, dberr = c.db.FindEntitiesByType(atype, since)
	})
	<-done
	close(done)

	if dberr != nil {
		return entities, err
	}

	c.Lock()
	defer c.Unlock()

	var results []*types.Entity
	for _, entity := range dbentities {
		if e, err := c.cache.CreateEntity(&types.Entity{
			CreatedAt: entity.CreatedAt,
			LastSeen:  entity.LastSeen,
			Asset:     entity.Asset,
		}); err == nil {
			results = append(results, e)
			if tags, err := c.cache.GetEntityTags(entity, c.start, "cache_find_entities_by_type"); err == nil && len(tags) > 0 {
				for _, tag := range tags {
					_ = c.cache.DeleteEntityTag(tag.ID)
				}
			}
			_ = c.createCacheEntityTag(entity, "cache_find_entities_by_type", since)
		}
	}
	return results, nil
}

// DeleteEntity implements the Repository interface.
func (c *Cache) DeleteEntity(id string) error {
	c.Lock()
	defer c.Unlock()

	err := c.cache.DeleteEntity(id)
	if err != nil {
		return err
	}

	entity, err := c.cache.FindEntityById(id)
	if err != nil {
		return nil
	}

	c.appendToDBQueue(func() {
		if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
			_ = c.db.DeleteEntity(e[0].ID)
		}
	})

	return nil
}
