// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

	var create bool
	if input.ID != "" {
		// If the entity ID is set, it means that the entity was previously created,
		// and we need to update that entity in the database regardless of frequency
		create = true
	} else if _, last, found := c.checkCacheEntityTag(entity, "cache_create_entity"); !found || last.Add(c.freq).Before(time.Now()) {
		create = true
	}

	if create {
		_, err = c.db.CreateEntity(&types.Entity{
			CreatedAt: input.CreatedAt,
			LastSeen:  input.LastSeen,
			Asset:     input.Asset,
		})
		if err == nil {
			_ = c.createCacheEntityTag(entity, "cache_create_entity", time.Now())
		}
	}

	return entity, err
}

// CreateAsset implements the Repository interface.
func (c *Cache) CreateAsset(asset oam.Asset) (*types.Entity, error) {
	entity, err := c.cache.CreateAsset(asset)
	if err != nil {
		return nil, err
	}

	if _, last, found := c.checkCacheEntityTag(entity, "cache_create_asset"); !found || last.Add(c.freq).Before(time.Now()) {
		_, err = c.db.CreateAsset(asset)
		if err == nil {
			_ = c.createCacheEntityTag(entity, "cache_create_asset", time.Now())
		}
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

	if ents, err := c.db.FindEntitiesByContent(entity.Asset, time.Time{}); err == nil && len(ents) > 0 {
		for _, e := range ents {
			_ = c.db.DeleteEntity(e.ID)
		}
	}

	return nil
}
