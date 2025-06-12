// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"errors"
	"time"

	"github.com/owasp-amass/asset-db/types"
)

func (c *Cache) createCacheEntityTag(entity *types.Entity, name, refID string, since time.Time) error {
	if entity == nil {
		return errors.New("entity cannot be nil")
	} else if name == "" {
		return errors.New("tag name cannot be empty")
	} else if refID == "" {
		return errors.New("reference ID cannot be empty")
	}
	// remove all existing tags with the same name
	if tags, err := c.cache.GetEntityTags(entity, c.start, name); err == nil {
		for _, tag := range tags {
			_ = c.cache.DeleteEntityTag(tag.ID)
		}
	}

	_, err := c.cache.CreateEntityProperty(entity, &types.CacheProperty{
		ID:        name,
		RefID:     refID,
		Timestamp: since.Format(time.RFC3339Nano),
	})
	return err
}

func (c *Cache) checkCacheEntityTag(entity *types.Entity, name string) (*types.EntityTag, time.Time, bool) {
	if entity == nil || name == "" {
		return nil, time.Time{}, false
	}

	if tags, err := c.cache.GetEntityTags(entity, c.start, name); err == nil && len(tags) == 1 {
		tag := tags[0]

		prop, ok := tag.Property.(*types.CacheProperty)
		if !ok {
			return nil, time.Time{}, false
		}
		// Parse the timestamp from the property
		t, err := time.Parse(time.RFC3339Nano, prop.Timestamp)
		if err != nil {
			return nil, time.Time{}, false
		}
		// Check if the tag is still valid based on the frequency
		if t.Add(c.freq).Before(time.Now()) {
			return tag, t, true
		}
		return tag, t, false
	}
	return nil, time.Time{}, false
}

func (c *Cache) createCacheEdgeTag(edge *types.Edge, name, refID string, since time.Time) error {
	if edge == nil {
		return errors.New("entity cannot be nil")
	} else if name == "" {
		return errors.New("tag name cannot be empty")
	} else if refID == "" {
		return errors.New("reference ID cannot be empty")
	}
	// remove all existing tags with the same name
	if tags, err := c.cache.GetEdgeTags(edge, c.start, name); err == nil {
		for _, tag := range tags {
			_ = c.cache.DeleteEdgeTag(tag.ID)
		}
	}

	_, err := c.cache.CreateEdgeProperty(edge, &types.CacheProperty{
		ID:        name,
		RefID:     refID,
		Timestamp: since.Format(time.RFC3339Nano),
	})
	return err
}

func (c *Cache) checkCacheEdgeTag(edge *types.Edge, name string) (*types.EdgeTag, time.Time, bool) {
	if edge == nil || name == "" {
		return nil, time.Time{}, false
	}

	if tags, err := c.cache.GetEdgeTags(edge, c.start, name); err == nil && len(tags) == 1 {
		tag := tags[0]

		prop, ok := tag.Property.(*types.CacheProperty)
		if !ok {
			return nil, time.Time{}, false
		}
		// Parse the timestamp from the property
		t, err := time.Parse(time.RFC3339Nano, prop.Timestamp)
		if err != nil {
			return nil, time.Time{}, false
		}
		// Check if the tag is still valid based on the frequency
		if t.Add(c.freq).Before(time.Now()) {
			return tag, t, true
		}
		return tag, t, false
	}
	return nil, time.Time{}, false
}
