// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"reflect"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/property"
)

// CreateEntityTag implements the Repository interface.
func (c *Cache) CreateEntityTag(entity *types.Entity, input *types.EntityTag) (*types.EntityTag, error) {
	c.Lock()
	defer c.Unlock()

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
	c.Lock()
	defer c.Unlock()

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
	c.Lock()
	defer c.Unlock()

	return c.cache.FindEntityTagById(id)
}

// GetEntityTags implements the Repository interface.
func (c *Cache) GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	if since.IsZero() || since.Before(c.start) {
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

		c.Lock()
		defer c.Unlock()

		if dberr == nil && len(dbtags) > 0 {
			for _, tag := range dbtags {
				_, _ = c.cache.CreateEntityTag(entity, &types.EntityTag{
					CreatedAt: tag.CreatedAt,
					LastSeen:  tag.LastSeen,
					Property:  tag.Property,
				})
			}
		}
	} else {
		c.Lock()
		defer c.Unlock()
	}

	return c.cache.GetEntityTags(entity, since, names...)
}

// DeleteEntityTag implements the Repository interface.
func (c *Cache) DeleteEntityTag(id string) error {
	c.Lock()
	defer c.Unlock()

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

// CreateEdgeTag implements the Repository interface.
func (c *Cache) CreateEdgeTag(edge *types.Edge, input *types.EdgeTag) (*types.EdgeTag, error) {
	c.Lock()
	defer c.Unlock()

	tag, err := c.cache.CreateEdgeTag(edge, input)
	if err != nil {
		return nil, err
	}

	edge2, err := c.cache.FindEdgeById(tag.Edge.ID)
	if err != nil {
		return nil, err
	}

	sub, err := c.cache.FindEntityById(edge2.FromEntity.ID)
	if err != nil {
		return nil, err
	}

	obj, err := c.cache.FindEntityById(edge2.ToEntity.ID)
	if err != nil {
		return nil, err
	}

	c.appendToDBQueue(func() {
		s, err := c.db.FindEntityByContent(sub.Asset, time.Time{})
		if err != nil || len(s) != 1 {
			return
		}

		o, err := c.db.FindEntityByContent(obj.Asset, time.Time{})
		if err != nil || len(o) != 1 {
			return
		}

		edges, err := c.db.OutgoingEdges(s[0], time.Time{}, edge.Relation.Label())
		if err != nil || len(edges) == 0 {
			return
		}

		var target *types.Edge
		for _, e := range edges {
			if e.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge2.Relation) {
				target = e
				break
			}
		}
		if target != nil {
			_, _ = c.db.CreateEdgeProperty(target, input.Property)
		}
	})

	return tag, nil
}

// CreateEdgeProperty implements the Repository interface.
func (c *Cache) CreateEdgeProperty(edge *types.Edge, property oam.Property) (*types.EdgeTag, error) {
	c.Lock()
	defer c.Unlock()

	tag, err := c.cache.CreateEdgeProperty(edge, property)
	if err != nil {
		return nil, err
	}

	edge2, err := c.cache.FindEdgeById(tag.Edge.ID)
	if err != nil {
		return nil, err
	}

	sub, err := c.cache.FindEntityById(edge2.FromEntity.ID)
	if err != nil {
		return nil, err
	}

	obj, err := c.cache.FindEntityById(edge2.ToEntity.ID)
	if err != nil {
		return nil, err
	}

	c.appendToDBQueue(func() {
		s, err := c.db.FindEntityByContent(sub.Asset, time.Time{})
		if err != nil || len(s) != 1 {
			return
		}

		o, err := c.db.FindEntityByContent(obj.Asset, time.Time{})
		if err != nil || len(o) != 1 {
			return
		}

		edges, err := c.db.OutgoingEdges(s[0], time.Time{}, edge.Relation.Label())
		if err != nil || len(edges) == 0 {
			return
		}

		var target *types.Edge
		for _, e := range edges {
			if e.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge2.Relation) {
				target = e
				break
			}
		}
		if target != nil {
			_, _ = c.db.CreateEdgeProperty(target, property)
		}
	})

	return tag, nil
}

// FindEdgeTagById implements the Repository interface.
func (c *Cache) FindEdgeTagById(id string) (*types.EdgeTag, error) {
	c.Lock()
	defer c.Unlock()

	return c.cache.FindEdgeTagById(id)
}

// GetEdgeTags implements the Repository interface.
func (c *Cache) GetEdgeTags(edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {
	if since.IsZero() || since.Before(c.start) {
		c.Lock()
		sub, err := c.cache.FindEntityById(edge.FromEntity.ID)
		if err != nil {
			c.Unlock()
			return nil, err
		}

		obj, err := c.cache.FindEntityById(edge.ToEntity.ID)
		if err != nil {
			c.Unlock()
			return nil, err
		}
		c.Unlock()

		var dberr error
		var dbtags []*types.EdgeTag
		done := make(chan struct{}, 1)
		c.appendToDBQueue(func() {
			defer func() { done <- struct{}{} }()

			s, err := c.db.FindEntityByContent(sub.Asset, time.Time{})
			if err != nil || len(s) != 1 {
				return
			}

			o, err := c.db.FindEntityByContent(obj.Asset, time.Time{})
			if err != nil || len(o) != 1 {
				return
			}

			edges, err := c.db.OutgoingEdges(s[0], time.Time{}, edge.Relation.Label())
			if err != nil || len(edges) == 0 {
				return
			}

			var target *types.Edge
			for _, e := range edges {
				if e.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge.Relation) {
					target = e
					break
				}
			}
			if target != nil {
				dbtags, dberr = c.db.GetEdgeTags(target, since)
			}
		})
		<-done
		close(done)

		c.Lock()
		defer c.Unlock()

		if dberr == nil && len(dbtags) > 0 {
			for _, tag := range dbtags {
				_, _ = c.cache.CreateEdgeTag(edge, &types.EdgeTag{
					CreatedAt: tag.CreatedAt,
					LastSeen:  tag.LastSeen,
					Property:  tag.Property,
				})
			}
		}
	} else {
		c.Lock()
		defer c.Unlock()
	}

	return c.cache.GetEdgeTags(edge, since, names...)
}

// DeleteEdgeTag implements the Repository interface.
func (c *Cache) DeleteEdgeTag(id string) error {
	c.Lock()
	defer c.Unlock()

	tag, err := c.cache.FindEdgeTagById(id)
	if err != nil {
		return err
	}

	edge2, err := c.cache.FindEdgeById(tag.Edge.ID)
	if err != nil {
		return err
	}

	sub, err := c.cache.FindEntityById(edge2.FromEntity.ID)
	if err != nil {
		return err
	}

	obj, err := c.cache.FindEntityById(edge2.ToEntity.ID)
	if err != nil {
		return err
	}

	if err := c.cache.DeleteEdgeTag(id); err != nil {
		return err
	}

	c.appendToDBQueue(func() {
		s, err := c.db.FindEntityByContent(sub.Asset, time.Time{})
		if err != nil || len(s) != 1 {
			return
		}

		o, err := c.db.FindEntityByContent(obj.Asset, time.Time{})
		if err != nil || len(o) != 1 {
			return
		}

		edges, err := c.db.OutgoingEdges(s[0], time.Time{}, tag.Edge.Relation.Label())
		if err != nil || len(edges) == 0 {
			return
		}

		var target *types.Edge
		for _, e := range edges {
			if e.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge2.Relation) {
				target = e
				break
			}
		}
		if target == nil {
			return
		}

		if tags, err := c.db.GetEdgeTags(target, time.Time{}, tag.Property.Name()); err == nil && len(tags) > 0 {
			for _, t := range tags {
				if tag.Property.Value() == t.Property.Value() {
					_ = c.db.DeleteEdgeTag(t.ID)
				}
			}
		}
	})

	return nil
}

func (c *Cache) createCacheEntityTag(entity *types.Entity, name string, since time.Time) error {
	_, err := c.cache.CreateEntityProperty(entity, &property.SimpleProperty{
		PropertyName:  name,
		PropertyValue: since.Format(time.RFC3339Nano),
	})
	return err
}

func (c *Cache) checkCacheEntityTag(entity *types.Entity, name string) (*types.EntityTag, time.Time, bool) {
	if tags, err := c.cache.GetEntityTags(entity, time.Time{}, name); err == nil && len(tags) == 1 {
		if t, err := time.Parse(time.RFC3339Nano, tags[0].Property.Value()); err == nil {
			return tags[0], t, true
		}
	}
	return nil, time.Time{}, false
}

func (c *Cache) createCacheEdgeTag(edge *types.Edge, name string, since time.Time) error {
	_, err := c.cache.CreateEdgeProperty(edge, &property.SimpleProperty{
		PropertyName:  name,
		PropertyValue: since.Format(time.RFC3339Nano),
	})
	return err
}

func (c *Cache) checkCacheEdgeTag(edge *types.Edge, name string) (*types.EdgeTag, time.Time, bool) {
	if tags, err := c.cache.GetEdgeTags(edge, time.Time{}, name); err == nil && len(tags) == 1 {
		if t, err := time.Parse(time.RFC3339Nano, tags[0].Property.Value()); err == nil {
			return tags[0], t, true
		}
	}
	return nil, time.Time{}, false
}
