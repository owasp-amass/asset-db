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

// CreateEntityTag implements the Repository interface.
func (c *Cache) CreateEntityTag(ctx context.Context, entity *types.Entity, input *types.EntityTag) (*types.EntityTag, error) {
	// if the tag already exists, then do not create it again
	if tags, err := c.cache.FindEntityTags(ctx, entity, time.Time{}, input.Property.Name()); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if input.Property.Value() == tag.Property.Value() && tag.LastSeen.Add(c.freq).After(time.Now()) {
				return tag, nil
			}
		}
	}

	tag, err := c.cache.CreateEntityTag(ctx, entity, input)
	if err != nil {
		return nil, err
	}

	ctag, _, _ := c.checkCacheEntityTag(entity, "cache_create_entity")
	if ctag == nil {
		return nil, errors.New("cache entity tag not found")
	}
	cp := ctag.Property.(*types.CacheProperty)

	_, err = c.db.CreateEntityTag(ctx, &types.Entity{ID: cp.RefID}, &types.EntityTag{
		CreatedAt: input.CreatedAt,
		LastSeen:  input.LastSeen,
		Property:  input.Property,
	})
	return tag, err
}

// CreateEntityProperty implements the Repository interface.
func (c *Cache) CreateEntityProperty(ctx context.Context, entity *types.Entity, property oam.Property) (*types.EntityTag, error) {
	// if the tag already exists, then do not create it again
	if tags, err := c.cache.FindEntityTags(ctx, entity, time.Time{}, property.Name()); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if property.Value() == tag.Property.Value() && tag.LastSeen.Add(c.freq).After(time.Now()) {
				return tag, nil
			}
		}
	}

	tag, err := c.cache.CreateEntityProperty(ctx, entity, property)
	if err != nil {
		return nil, err
	}

	ctag, _, _ := c.checkCacheEntityTag(entity, "cache_create_entity")
	if ctag == nil {
		return nil, errors.New("cache entity tag not found")
	}
	cp := ctag.Property.(*types.CacheProperty)

	_, err = c.db.CreateEntityProperty(ctx, &types.Entity{ID: cp.RefID}, property)
	return tag, err
}

// FindEntityTagById implements the Repository interface.
func (c *Cache) FindEntityTagById(ctx context.Context, id string) (*types.EntityTag, error) {
	return c.cache.FindEntityTagById(ctx, id)
}

// FindEntityTags implements the Repository interface.
func (c *Cache) FindEntityTags(ctx context.Context, entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
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

		dbtags, dberr := c.db.FindEntityTags(ctx, &types.Entity{ID: refID}, since)
		if dberr != nil {
			return nil, dberr
		}
		_ = c.createCacheEntityTag(entity, "cache_get_entity_tags", refID, since)

		if dberr == nil && len(dbtags) > 0 {
			for _, tag := range dbtags {
				_, _ = c.cache.CreateEntityTag(ctx, entity, &types.EntityTag{
					CreatedAt: tag.CreatedAt,
					LastSeen:  tag.LastSeen,
					Property:  tag.Property,
				})
			}
		}
	}

	return c.cache.FindEntityTags(ctx, entity, since, names...)
}

// DeleteEntityTag implements the Repository interface.
func (c *Cache) DeleteEntityTag(ctx context.Context, id string) error {
	tag, err := c.cache.FindEntityTagById(ctx, id)
	if err != nil {
		return err
	}

	ctag, _, _ := c.checkCacheEntityTag(tag.Entity, "cache_create_entity")
	if ctag == nil {
		return errors.New("cache entity tag not found")
	}
	cp := ctag.Property.(*types.CacheProperty)

	if err := c.db.DeleteEntityTag(ctx, cp.RefID); err != nil {
		return err
	}

	return c.cache.DeleteEntityTag(ctx, id)
}
