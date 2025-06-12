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

	ctag, _, _ := c.checkCacheEntityTag(entity, "cache_create_entity")
	if ctag == nil {
		return nil, errors.New("cache entity tag not found")
	}
	cp := ctag.Property.(*types.CacheProperty)

	_, err = c.db.CreateEntityTag(&types.Entity{ID: cp.RefID}, &types.EntityTag{
		CreatedAt: input.CreatedAt,
		LastSeen:  input.LastSeen,
		Property:  input.Property,
	})
	return tag, err
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

	ctag, _, _ := c.checkCacheEntityTag(entity, "cache_create_entity")
	if ctag == nil {
		return nil, errors.New("cache entity tag not found")
	}
	cp := ctag.Property.(*types.CacheProperty)

	_, err = c.db.CreateEntityProperty(&types.Entity{ID: cp.RefID}, property)
	return tag, err
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
					_ = c.createCacheEntityTag(entity, "cache_create_entity", dbentities[i].ID, time.Now())
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
	var refID string
	var dbquery, found bool

	if since.IsZero() || since.Before(c.start) {
		if tag, ts, _ := c.checkCacheEntityTag(entity, "cache_get_entity_tags"); tag == nil {
			dbquery = true
		} else if since.Before(ts) {
			found = true
			dbquery = true
			refID = tag.Property.Value()
		}
	}

	if dbquery {
		if !found {
			ctag, _, _ := c.checkCacheEntityTag(entity, "cache_create_entity")
			if ctag == nil {
				return nil, errors.New("cache entity tag not found")
			}
			cp := ctag.Property.(*types.CacheProperty)
			refID = cp.RefID
		}

		dbtags, dberr := c.db.GetEntityTags(&types.Entity{ID: refID}, since)
		if dberr != nil {
			return nil, dberr
		}
		_ = c.createCacheEntityTag(entity, "cache_get_entity_tags", refID, since)

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

	ctag, _, _ := c.checkCacheEntityTag(tag.Entity, "cache_create_entity")
	if ctag == nil {
		return errors.New("cache entity tag not found")
	}
	cp := ctag.Property.(*types.CacheProperty)

	if err := c.db.DeleteEntityTag(cp.RefID); err != nil {
		return err
	}

	return c.cache.DeleteEntityTag(id)
}
