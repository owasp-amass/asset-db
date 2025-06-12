// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"encoding/json"
	"time"

	"github.com/owasp-amass/asset-db/types"
	model "github.com/owasp-amass/open-asset-model"
)

const CachePropertyType model.PropertyType = "CacheProperty"

// CacheProperty represents a cache property in the cached graph.
type CacheProperty struct {
	ID        string `json:"id"`
	RefID     string `json:"ref_id"`
	Timestamp string `json:"timestamp"`
}

// Name implements the Property interface.
func (p CacheProperty) Name() string {
	return p.ID
}

// Value implements the Property interface.
func (p CacheProperty) Value() string {
	return p.RefID
}

// PropertyType implements the Property interface.
func (p CacheProperty) PropertyType() model.PropertyType {
	return CachePropertyType
}

// JSON implements the Property interface.
func (p CacheProperty) JSON() ([]byte, error) {
	return json.Marshal(p)
}

func (c *Cache) createCacheEntityTag(entity *types.Entity, name, refID string, since time.Time) error {
	// remove all existing tags with the same name
	if tags, err := c.cache.GetEntityTags(entity, c.start, name); err == nil {
		for _, tag := range tags {
			_ = c.cache.DeleteEntityTag(tag.ID)
		}
	}

	_, err := c.cache.CreateEntityProperty(entity, &CacheProperty{
		ID:        name,
		RefID:     refID,
		Timestamp: since.Format(time.RFC3339Nano),
	})
	return err
}

func (c *Cache) checkCacheEntityTag(entity *types.Entity, name string) (*types.EntityTag, time.Time, bool) {
	if tags, err := c.cache.GetEntityTags(entity, c.start, name); err == nil && len(tags) == 1 {
		tag := tags[0]

		prop, ok := tag.Property.(*CacheProperty)
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
	// remove all existing tags with the same name
	if tags, err := c.cache.GetEdgeTags(edge, c.start, name); err == nil {
		for _, tag := range tags {
			_ = c.cache.DeleteEdgeTag(tag.ID)
		}
	}

	_, err := c.cache.CreateEdgeProperty(edge, &CacheProperty{
		ID:        name,
		RefID:     refID,
		Timestamp: since.Format(time.RFC3339Nano),
	})
	return err
}

func (c *Cache) checkCacheEdgeTag(edge *types.Edge, name string) (*types.EdgeTag, time.Time, bool) {
	if tags, err := c.cache.GetEdgeTags(edge, c.start, name); err == nil && len(tags) == 1 {
		tag := tags[0]

		prop, ok := tag.Property.(*CacheProperty)
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
