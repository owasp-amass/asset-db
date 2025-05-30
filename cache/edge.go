// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"reflect"
	"time"

	"github.com/owasp-amass/asset-db/types"
)

// CreateEdge implements the Repository interface.
func (c *Cache) CreateEdge(edge *types.Edge) (*types.Edge, error) {
	e, err := c.cache.CreateEdge(edge)
	if err != nil {
		return nil, err
	}

	if _, last, found := c.checkCacheEdgeTag(edge, "cache_create_edge"); !found || last.Add(c.freq).Before(time.Now()) {
		sub, err := c.cache.FindEntityById(e.FromEntity.ID)
		if err != nil {
			return nil, err
		}

		obj, err := c.cache.FindEntityById(e.ToEntity.ID)
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

		if _, err = c.db.CreateEdge(&types.Edge{
			CreatedAt:  edge.CreatedAt,
			LastSeen:   edge.LastSeen,
			Relation:   e.Relation,
			FromEntity: s[0],
			ToEntity:   o[0],
		}); err != nil {
			return nil, err
		}

		_ = c.createCacheEdgeTag(e, "cache_create_edge", time.Now())
	}

	return e, err
}

// FindEdgeById implements the Repository interface.
func (c *Cache) FindEdgeById(id string) (*types.Edge, error) {
	return c.cache.FindEdgeById(id)
}

// IncomingEdges implements the Repository interface.
func (c *Cache) IncomingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	var dbquery bool

	if since.IsZero() || since.Before(c.start) {
		if _, last, found := c.checkCacheEntityTag(entity, "cache_incoming_edges"); !found || since.Before(last) {
			dbquery = true
		}
	}

	if dbquery {
		if e, err := c.db.FindEntitiesByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
			_ = c.createCacheEntityTag(entity, "cache_incoming_edges", since)

			if dbedges, dberr := c.db.IncomingEdges(e[0], since); dberr == nil && len(dbedges) > 0 {
				for _, edge := range dbedges {
					e, err := c.db.FindEntityById(edge.ToEntity.ID)
					if err != nil || e == nil {
						continue
					}
					edge.FromEntity = e

					e, err = c.cache.CreateEntity(&types.Entity{
						CreatedAt: edge.FromEntity.CreatedAt,
						LastSeen:  edge.FromEntity.LastSeen,
						Asset:     edge.FromEntity.Asset,
					})

					if err == nil && e != nil {
						_, _ = c.cache.CreateEdge(&types.Edge{
							CreatedAt:  edge.CreatedAt,
							LastSeen:   edge.LastSeen,
							Relation:   edge.Relation,
							FromEntity: e,
							ToEntity:   entity,
						})
					}
				}
			}
		}
	}

	return c.cache.IncomingEdges(entity, since, labels...)
}

// OutgoingEdges implements the Repository interface.
func (c *Cache) OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	var dbquery bool

	if since.IsZero() || since.Before(c.start) {
		if _, last, found := c.checkCacheEntityTag(entity, "cache_outgoing_edges"); !found || since.Before(last) {
			dbquery = true
		}
	}

	if dbquery {
		if e, err := c.db.FindEntitiesByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
			_ = c.createCacheEntityTag(entity, "cache_outgoing_edges", since)

			if dbedges, dberr := c.db.OutgoingEdges(e[0], since); dberr == nil && len(dbedges) > 0 {
				for _, edge := range dbedges {
					e, err := c.db.FindEntityById(edge.ToEntity.ID)
					if err != nil || e == nil {
						continue
					}
					edge.ToEntity = e

					e, err = c.cache.CreateEntity(&types.Entity{
						CreatedAt: edge.ToEntity.CreatedAt,
						LastSeen:  edge.ToEntity.LastSeen,
						Asset:     edge.ToEntity.Asset,
					})

					if err == nil && e != nil {
						_, _ = c.cache.CreateEdge(&types.Edge{
							CreatedAt:  edge.CreatedAt,
							LastSeen:   edge.LastSeen,
							Relation:   edge.Relation,
							FromEntity: entity,
							ToEntity:   e,
						})
					}
				}
			}
		}
	}

	return c.cache.OutgoingEdges(entity, since, labels...)
}

// DeleteEdge implements the Repository interface.
func (c *Cache) DeleteEdge(id string) error {
	edge, err := c.cache.FindEdgeById(id)
	if err != nil {
		return err
	}

	sub, err := c.cache.FindEntityById(edge.FromEntity.ID)
	if err != nil {
		return err
	}

	obj, err := c.cache.FindEntityById(edge.ToEntity.ID)
	if err != nil {
		return err
	}

	if err := c.cache.DeleteEdge(id); err != nil {
		return err
	}

	s, err := c.db.FindEntitiesByContent(sub.Asset, time.Time{})
	if err != nil || len(s) != 1 {
		return err
	}

	o, err := c.db.FindEntitiesByContent(obj.Asset, time.Time{})
	if err != nil || len(o) != 1 {
		return err
	}

	edges, err := c.db.OutgoingEdges(s[0], time.Time{}, edge.Relation.Label())
	if err != nil || len(edges) == 0 {
		return err
	}

	var target *types.Edge
	for _, e := range edges {
		if e.ToEntity.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge.Relation) {
			target = e
			break
		}
	}
	if target != nil {
		err = c.db.DeleteEdge(target.ID)
	}

	return err
}
