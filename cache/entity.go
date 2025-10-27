// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"errors"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// CreateEntity implements the Repository interface.
func (c *Cache) CreateEntity(ctx context.Context, input *types.Entity) (*types.Entity, error) {
	entity, err := c.cache.CreateEntity(ctx, input)
	if err != nil {
		return nil, err
	}

	var create bool
	if input.ID != "" {
		// If the entity ID is set, it means that the entity was previously created,
		// and we need to update that entity in the database regardless of frequency
		create = true
	} else if tag, _, ok := c.checkCacheEntityTag(entity, "cache_create_entity"); tag == nil || ok {
		create = true
	}

	if create {
		if e, err := c.db.CreateEntity(ctx, &types.Entity{
			CreatedAt: input.CreatedAt,
			LastSeen:  input.LastSeen,
			Asset:     input.Asset,
		}); err == nil {
			_ = c.createCacheEntityTag(entity, "cache_create_entity", e.ID, time.Now())
		}
	}

	return entity, err
}

// CreateAsset implements the Repository interface.
func (c *Cache) CreateAsset(ctx context.Context, asset oam.Asset) (*types.Entity, error) {
	entity, err := c.cache.CreateAsset(ctx, asset)
	if err != nil {
		return nil, err
	}

	if tag, _, ok := c.checkCacheEntityTag(entity, "cache_create_entity"); tag == nil || ok {
		if e, err := c.db.CreateAsset(ctx, asset); err == nil {
			_ = c.createCacheEntityTag(entity, "cache_create_entity", e.ID, time.Now())
		}
	}

	return entity, err
}

// FindEntityById implements the Repository interface.
func (c *Cache) FindEntityById(ctx context.Context, id string) (*types.Entity, error) {
	return c.cache.FindEntityById(ctx, id)
}

// FindEntitiesByContent implements the Repository interface.
func (c *Cache) FindEntitiesByContent(ctx context.Context, etype string, since time.Time, filters types.ContentFilters) ([]*types.Entity, error) {
	entities, err := c.cache.FindEntitiesByContent(ctx, etype, since, filters)
	if err == nil && len(entities) > 0 {
		return entities, nil
	}

	if !since.IsZero() && !since.Before(c.start) {
		return nil, err
	}

	dbentities, dberr := c.db.FindEntitiesByContent(ctx, etype, since, filters)
	if dberr != nil {
		return entities, err
	}

	var results []*types.Entity
	for _, entity := range dbentities {
		if e, err := c.cache.CreateEntity(ctx, &types.Entity{
			CreatedAt: entity.CreatedAt,
			LastSeen:  entity.LastSeen,
			Asset:     entity.Asset,
		}); err == nil {
			results = append(results, e)
			_ = c.createCacheEntityTag(e, "cache_create_entity", entity.ID, time.Now())
		}
	}

	if len(results) == 0 {
		return nil, errors.New("zero entities found")
	}
	return results, nil
}

// FindOneEntityByContent implements the Repository interface.
func (c *Cache) FindOneEntityByContent(ctx context.Context, etype string, since time.Time, filters types.ContentFilters) (*types.Entity, error) {
	entities, err := c.FindEntitiesByContent(ctx, etype, since, filters)
	if err != nil {
		return nil, err
	}
	if len(entities) == 0 {
		return nil, errors.New("zero entities found")
	}
	return entities[0], nil
}

// FindEntitiesByType implements the Repository interface.
func (c *Cache) FindEntitiesByType(ctx context.Context, atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	entities, err := c.cache.FindEntitiesByType(ctx, atype, since)
	if err == nil && len(entities) > 0 {
		if !since.IsZero() && !since.Before(c.start) {
			return entities, err
		}
		if tag, ts, _ := c.checkCacheEntityTag(entities[0], "cache_find_entities_by_type"); tag != nil && !since.Before(ts) {
			return entities, err
		}
	}

	dbentities, dberr := c.db.FindEntitiesByType(ctx, atype, since)
	if dberr != nil {
		return entities, err
	}

	var results []*types.Entity
	for _, entity := range dbentities {
		if e, err := c.cache.CreateEntity(ctx, &types.Entity{
			CreatedAt: entity.CreatedAt,
			LastSeen:  entity.LastSeen,
			Asset:     entity.Asset,
		}); err == nil {
			results = append(results, e)
			_ = c.createCacheEntityTag(e, "cache_create_entity", entity.ID, time.Now())
			_ = c.createCacheEntityTag(entity, "cache_find_entities_by_type", entity.ID, since)
		}
	}
	return results, nil
}

// DeleteEntity implements the Repository interface.
func (c *Cache) DeleteEntity(ctx context.Context, id string) error {
	tag, _, _ := c.checkCacheEntityTag(&types.Entity{ID: id}, "cache_create_entity")
	if tag == nil {
		return errors.New("cache entity tag not found")
	}
	cp := tag.Property.(*types.CacheProperty)

	if err := c.cache.DeleteEntity(ctx, id); err != nil {
		return err
	}
	return c.db.DeleteEntity(ctx, cp.RefID)
}
