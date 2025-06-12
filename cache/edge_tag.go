// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"errors"
	"reflect"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// CreateEdgeTag implements the Repository interface.
func (c *Cache) CreateEdgeTag(edge *types.Edge, input *types.EdgeTag) (*types.EdgeTag, error) {
	// if the tag already exists, then do not create it again
	if tags, err := c.cache.GetEdgeTags(edge, time.Time{}, input.Property.Name()); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if input.Property.Value() == tag.Property.Value() && tag.LastSeen.Add(c.freq).After(time.Now()) {
				return tag, nil
			}
		}
	}

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

	s, err := c.db.FindEntitiesByContent(sub.Asset, time.Time{})
	if err != nil || len(s) != 1 {
		return nil, err
	}

	o, err := c.db.FindEntitiesByContent(obj.Asset, time.Time{})
	if err != nil || len(o) != 1 {
		return nil, err
	}

	edges, err := c.db.OutgoingEdges(s[0], time.Time{}, edge.Relation.Label())
	if err != nil || len(edges) == 0 {
		return nil, err
	}

	var target *types.Edge
	for _, e := range edges {
		if e.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge2.Relation) {
			target = e
			break
		}
	}
	if target != nil {
		_, err = c.db.CreateEdgeProperty(target, input.Property)
	}

	return tag, err
}

// CreateEdgeProperty implements the Repository interface.
func (c *Cache) CreateEdgeProperty(edge *types.Edge, property oam.Property) (*types.EdgeTag, error) {
	// if the tag already exists, then do not create it again
	if tags, err := c.cache.GetEdgeTags(edge, time.Time{}, property.Name()); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if property.Value() == tag.Property.Value() && tag.LastSeen.Add(c.freq).After(time.Now()) {
				return tag, nil
			}
		}
	}

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

	s, err := c.db.FindEntitiesByContent(sub.Asset, time.Time{})
	if err != nil || len(s) != 1 {
		return nil, err
	}

	o, err := c.db.FindEntitiesByContent(obj.Asset, time.Time{})
	if err != nil || len(o) != 1 {
		return nil, err
	}

	edges, err := c.db.OutgoingEdges(s[0], time.Time{}, edge.Relation.Label())
	if err != nil || len(edges) == 0 {
		return nil, err
	}

	var target *types.Edge
	for _, e := range edges {
		if e.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge2.Relation) {
			target = e
			break
		}
	}
	if target != nil {
		_, err = c.db.CreateEdgeProperty(target, property)
	}

	return tag, err
}

// FindEdgeTagById implements the Repository interface.
func (c *Cache) FindEdgeTagById(id string) (*types.EdgeTag, error) {
	return c.cache.FindEdgeTagById(id)
}

// FindEdgeTagsByContent implements the Repository interface.
// TODO: Consider adding a check for the last time the cache was updated
func (c *Cache) FindEdgeTagsByContent(prop oam.Property, since time.Time) ([]*types.EdgeTag, error) {
	if since.IsZero() || since.Before(c.start) {
		var dbedges []*types.Edge
		var froms, tos []*types.Entity

		dbtags, dberr := c.db.FindEdgeTagsByContent(prop, since)
		if dberr == nil && len(dbtags) > 0 {
			for _, tag := range dbtags {
				if edge, err := c.db.FindEdgeById(tag.Edge.ID); err == nil && edge != nil {
					from, err := c.db.FindEntityById(edge.FromEntity.ID)
					if err != nil {
						continue
					}
					to, err := c.db.FindEntityById(edge.ToEntity.ID)
					if err != nil {
						continue
					}
					tos = append(tos, to)
					froms = append(froms, from)
					dbedges = append(dbedges, edge)
				}
			}
		}

		if dberr == nil {
			for i, tag := range dbtags {
				from, err := c.cache.CreateEntity(&types.Entity{
					CreatedAt: froms[i].CreatedAt,
					LastSeen:  froms[i].LastSeen,
					Asset:     froms[i].Asset,
				})
				if err != nil || from == nil {
					continue
				}

				to, err := c.cache.CreateEntity(&types.Entity{
					CreatedAt: tos[i].CreatedAt,
					LastSeen:  tos[i].LastSeen,
					Asset:     tos[i].Asset,
				})
				if err != nil || to == nil {
					continue
				}

				edge, err := c.cache.CreateEdge(&types.Edge{
					CreatedAt:  dbedges[i].CreatedAt,
					LastSeen:   dbedges[i].LastSeen,
					Relation:   dbedges[i].Relation,
					FromEntity: from,
					ToEntity:   to,
				})
				if err != nil || edge == nil {
					continue
				}

				_, _ = c.cache.CreateEdgeTag(edge, &types.EdgeTag{
					CreatedAt: tag.CreatedAt,
					LastSeen:  tag.LastSeen,
					Property:  tag.Property,
				})
			}
		}
	}

	return c.cache.FindEdgeTagsByContent(prop, since)
}

// GetEdgeTags implements the Repository interface.
func (c *Cache) GetEdgeTags(edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {
	var dbquery bool

	if since.IsZero() || since.Before(c.start) {
		if tag, ts, _ := c.checkCacheEdgeTag(edge, "cache_get_edge_tags"); tag == nil || since.Before(ts) {
			dbquery = true
		}
	}

	if dbquery {
		ctag, _, _ := c.checkCacheEdgeTag(edge, "cache_create_edge")
		if ctag == nil {
			return nil, errors.New("cache edge tag not found")
		}
		refID := ctag.Property.Value()

		dbtags, dberr := c.db.GetEdgeTags(&types.Edge{ID: refID}, since)
		_ = c.createCacheEdgeTag(edge, "cache_get_edge_tags", refID, since)

		if dberr == nil && len(dbtags) > 0 {
			for _, tag := range dbtags {
				_, _ = c.cache.CreateEdgeTag(edge, &types.EdgeTag{
					CreatedAt: tag.CreatedAt,
					LastSeen:  tag.LastSeen,
					Property:  tag.Property,
				})
			}
		}
	}

	return c.cache.GetEdgeTags(edge, since, names...)
}

// DeleteEdgeTag implements the Repository interface.
func (c *Cache) DeleteEdgeTag(id string) error {
	tag, err := c.cache.FindEdgeTagById(id)
	if err != nil {
		return err
	}

	ctag, _, _ := c.checkCacheEdgeTag(tag.Edge, "cache_create_edge")
	if ctag == nil {
		return err
	}
	refID := ctag.Property.Value()

	if err := c.cache.DeleteEdgeTag(id); err != nil {
		return err
	}

	var ferr error
	if tags, err := c.db.GetEdgeTags(&types.Edge{ID: refID}, time.Time{}, tag.Property.Name()); err == nil && len(tags) > 0 {
		for _, t := range tags {
			if tag.Property.Value() == t.Property.Value() {
				if err := c.db.DeleteEdgeTag(t.ID); err != nil {
					ferr = err
				}
			}
		}
	}
	return ferr
}
