// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"errors"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// CreateEntity implements the Repository interface.
func (c *Cache) CreateEntity(input *types.Entity) (*types.Entity, error) {
	entity, err := c.cache.CreateEntity(input)
	if err != nil {
		return nil, err
	}

	if tag, last, found := c.checkCacheEntityTag(entity, "cache_create_entity"); !found || last.Add(c.freq).Before(time.Now()) {
		if found {
			_ = c.cache.DeleteEntityTag(tag.ID)
		}
		_ = c.createCacheEntityTag(entity, "cache_create_entity", time.Now())

		_, err = c.db.CreateEntity(&types.Entity{
			CreatedAt: input.CreatedAt,
			LastSeen:  input.LastSeen,
			Asset:     input.Asset,
		})
	}

	return entity, err
}

// CreateAsset implements the Repository interface.
func (c *Cache) CreateAsset(asset oam.Asset) (*types.Entity, error) {
	entity, err := c.cache.CreateAsset(asset)
	if err != nil {
		return nil, err
	}

	if tag, last, found := c.checkCacheEntityTag(entity, "cache_create_asset"); !found || last.Add(c.freq).Before(time.Now()) {
		if found {
			_ = c.cache.DeleteEntityTag(tag.ID)
		}
		_ = c.createCacheEntityTag(entity, "cache_create_asset", time.Now())

		_, err = c.db.CreateAsset(asset)
	}

	return entity, err
}

// FindEntityById implements the Repository interface.
func (c *Cache) FindEntityById(id string) (*types.Entity, error) {
	return c.cache.FindEntityById(id)
}

// FindEntitiesByContent implements the Repository interface.
func (c *Cache) FindEntitiesByContent(asset oam.Asset, since time.Time) ([]*types.Entity, error) {
	entities, err := c.cache.FindEntitiesByContent(asset, since)
	if err == nil && len(entities) > 0 {
		return entities, nil
	}

	if !since.IsZero() && !since.Before(c.start) {
		return nil, err
	}

	dbentities, dberr := c.db.FindEntitiesByContent(asset, since)
	if dberr != nil {
		return entities, err
	}

	var results []*types.Entity
	for _, entity := range dbentities {
		if e, err := c.cache.CreateEntity(&types.Entity{
			CreatedAt: entity.CreatedAt,
			LastSeen:  entity.LastSeen,
			Asset:     entity.Asset,
		}); err == nil {
			results = append(results, e)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("zero entities found")
	}
	return results, nil
}

// FindEntitiesByType implements the Repository interface.
func (c *Cache) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	entities, err := c.cache.FindEntitiesByType(atype, since)
	if err == nil && len(entities) > 0 {
		if !since.IsZero() && !since.Before(c.start) {
			return entities, err
		}
		if _, last, found := c.checkCacheEntityTag(entities[0], "cache_find_entities_by_type"); found && !since.Before(last) {
			return entities, err
		}
	}

	dbentities, dberr := c.db.FindEntitiesByType(atype, since)
	if dberr != nil {
		return entities, err
	}

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
	entity, err := c.cache.FindEntityById(id)
	if err != nil {
		return err
	}

	err = c.cache.DeleteEntity(id)
	if err != nil {
		return err
	}

	if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
		_ = c.db.DeleteEntity(e[0].ID)
	}

	return nil
}
