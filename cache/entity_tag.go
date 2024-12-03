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

	c.appendToDBQueue(func() {
		if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
			_, _ = c.db.CreateEntityTag(e[0], &types.EntityTag{
				CreatedAt: input.CreatedAt,
				LastSeen:  input.LastSeen,
				Property:  input.Property,
			})
		}
	})

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

	c.appendToDBQueue(func() {
		if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
			_, _ = c.db.CreateEntityProperty(e[0], property)
		}
	})

	return tag, nil
}

// FindEntityTagById implements the Repository interface.
func (c *Cache) FindEntityTagById(id string) (*types.EntityTag, error) {
	return c.cache.FindEntityTagById(id)
}

// FindEntityTagsByContent implements the Repository interface.
func (c *Cache) FindEntityTagsByContent(prop oam.Property, since time.Time) ([]*types.EntityTag, error) {
	tags, err := c.cache.FindEntityTagsByContent(prop, since)
	if err == nil && len(tags) > 0 {
		return tags, nil
	}

	if !since.IsZero() && !since.Before(c.start) {
		return nil, err
	}

	var dberr error
	var dbtags []*types.EntityTag
	var dbentities []*types.Entity
	done := make(chan struct{}, 1)
	c.appendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		dbtags, dberr = c.db.FindEntityTagsByContent(prop, since)
		if dberr == nil && len(dbtags) > 0 {
			for _, tag := range dbtags {
				if entity, err := c.db.FindEntityById(tag.Entity.ID); err == nil && entity != nil {
					dbentities = append(dbentities, entity)
				}
			}
		}
	})
	<-done
	close(done)

	if dberr != nil {
		return tags, err
	}

	var results []*types.EntityTag
	for i, tag := range dbtags {
		entity, err := c.cache.CreateEntity(dbentities[i])
		if err != nil || entity == nil {
			continue
		}

		if e, err := c.cache.CreateEntityTag(entity, &types.EntityTag{
			CreatedAt: tag.CreatedAt,
			LastSeen:  tag.LastSeen,
			Property:  tag.Property,
		}); err == nil {
			results = append(results, e)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("zero entity tags found")
	}
	return results, nil
}

// GetEntityTags implements the Repository interface.
func (c *Cache) GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	var dbquery bool

	if since.IsZero() || since.Before(c.start) {
		if tag, last, found := c.checkCacheEntityTag(entity, "cache_get_entity_tags"); !found || since.Before(last) {
			dbquery = true
			if found {
				_ = c.cache.DeleteEntityTag(tag.ID)
			}
			_ = c.createCacheEntityTag(entity, "cache_get_entity_tags", since)
		}
	}

	if dbquery {
		var dberr error
		var dbtags []*types.EntityTag

		done := make(chan struct{}, 1)
		c.appendToDBQueue(func() {
			defer func() { done <- struct{}{} }()

			if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
				dbtags, dberr = c.db.GetEntityTags(e[0], since)
			}
		})
		<-done
		close(done)

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

	c.appendToDBQueue(func() {
		if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
			if tags, err := c.db.GetEntityTags(e[0], time.Time{}, tag.Property.Name()); err == nil && len(tags) > 0 {
				for _, t := range tags {
					if t.Property.Value() == tag.Property.Value() {
						_ = c.db.DeleteEntityTag(t.ID)
					}
				}
			}
		}
	})

	return nil
}
