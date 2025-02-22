// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// CreateEntityTag implements the Repository interface.
func (c *Cache) CreateEntityTag(entity *types.Entity, input *types.EntityTag) (*types.EntityTag, error) {
	// if the tag already exists, then do not create it again
	if tags, err := c.cache.GetEntityTags(entity, time.Time{}, input.Property.Name()); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if input.Property.Value() == tag.Property.Value() && tag.LastSeen.Add(c.freq).After(time.Now()) {
				return tag, nil
			}
		}
	}

	tag, err := c.cache.CreateEntityTag(entity, input)
	if err != nil {
		return nil, err
	}

	if e, err := c.db.FindEntitiesByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
		_, _ = c.db.CreateEntityTag(e[0], &types.EntityTag{
			CreatedAt: input.CreatedAt,
			LastSeen:  input.LastSeen,
			Property:  input.Property,
		})
	}

	return tag, nil
}

// CreateEntityProperty implements the Repository interface.
func (c *Cache) CreateEntityProperty(entity *types.Entity, property oam.Property) (*types.EntityTag, error) {
	// if the tag already exists, then do not create it again
	if tags, err := c.cache.GetEntityTags(entity, time.Time{}, property.Name()); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if property.Value() == tag.Property.Value() && tag.LastSeen.Add(c.freq).After(time.Now()) {
				return tag, nil
			}
		}
	}

	tag, err := c.cache.CreateEntityProperty(entity, property)
	if err != nil {
		return nil, err
	}

	if e, err := c.db.FindEntitiesByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
		_, _ = c.db.CreateEntityProperty(e[0], property)
	}

	return tag, nil
}

// FindEntityTagById implements the Repository interface.
func (c *Cache) FindEntityTagById(id string) (*types.EntityTag, error) {
	return c.cache.FindEntityTagById(id)
}

// FindEntityTagsByContent implements the Repository interface.
// TODO: Consider adding a check for the last time the cache was updated
func (c *Cache) FindEntityTagsByContent(prop oam.Property, since time.Time) ([]*types.EntityTag, error) {
	if since.IsZero() || since.Before(c.start) {
		var dbentities []*types.Entity

		dbtags, dberr := c.db.FindEntityTagsByContent(prop, since)
		if dberr == nil && len(dbtags) > 0 {
			for _, tag := range dbtags {
				if entity, err := c.db.FindEntityById(tag.Entity.ID); err == nil && entity != nil {
					dbentities = append(dbentities, entity)
				}
			}
		}

		if dberr == nil {
			for i, tag := range dbtags {
				if entity, err := c.cache.CreateEntity(&types.Entity{
					CreatedAt: dbentities[i].CreatedAt,
					LastSeen:  dbentities[i].LastSeen,
					Asset:     dbentities[i].Asset,
				}); err == nil && entity != nil {
					_, _ = c.cache.CreateEntityTag(entity, &types.EntityTag{
						CreatedAt: tag.CreatedAt,
						LastSeen:  tag.LastSeen,
						Property:  tag.Property,
						Entity:    entity,
					})
				}
			}
		}
	}

	return c.cache.FindEntityTagsByContent(prop, since)
}

// GetEntityTags implements the Repository interface.
func (c *Cache) GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	var dbquery bool

	if since.IsZero() || since.Before(c.start) {
		if _, last, found := c.checkCacheEntityTag(entity, "cache_get_entity_tags"); !found || since.Before(last) {
			dbquery = true
		}
	}

	if dbquery {
		var dberr error
		var dbtags []*types.EntityTag

		if e, err := c.db.FindEntitiesByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
			dbtags, dberr = c.db.GetEntityTags(e[0], since)
			_ = c.createCacheEntityTag(entity, "cache_get_entity_tags", since)
		}

		if dberr == nil && len(dbtags) > 0 {
			for _, tag := range dbtags {
				_, _ = c.cache.CreateEntityTag(entity, &types.EntityTag{
					CreatedAt: tag.CreatedAt,
					LastSeen:  tag.LastSeen,
					Property:  tag.Property,
				})
			}
		}
	}

	return c.cache.GetEntityTags(entity, since, names...)
}

// DeleteEntityTag implements the Repository interface.
func (c *Cache) DeleteEntityTag(id string) error {
	tag, err := c.cache.FindEntityTagById(id)
	if err != nil {
		return err
	}

	entity, err := c.cache.FindEntityById(tag.Entity.ID)
	if err != nil {
		return err
	}

	if err := c.cache.DeleteEntityTag(id); err != nil {
		return err
	}

	if e, err := c.db.FindEntitiesByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
		if tags, err := c.db.GetEntityTags(e[0], time.Time{}, tag.Property.Name()); err == nil && len(tags) > 0 {
			for _, t := range tags {
				if t.Property.Value() == tag.Property.Value() {
					_ = c.db.DeleteEntityTag(t.ID)
				}
			}
		}
	}

	return nil
}
