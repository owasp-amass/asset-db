// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"errors"
	"time"

	"github.com/owasp-amass/asset-db/types"
)

// CreateEdge implements the Repository interface.
func (c *Cache) CreateEdge(ctx context.Context, edge *types.Edge) (*types.Edge, error) {
	e, err := c.cache.CreateEdge(ctx, edge)
	if err != nil {
		return nil, err
	}

	if tag, _, ok := c.checkCacheEdgeTag(edge, "cache_create_edge"); tag == nil || ok {
		stag, _, _ := c.checkCacheEntityTag(e.FromEntity, "cache_create_entity")
		if stag == nil {
			return nil, errors.New("cache entity tag not found")
		}
		scp := stag.Property.(*types.CacheProperty)

		otag2, _, _ := c.checkCacheEntityTag(e.ToEntity, "cache_create_entity")
		if otag2 == nil {
			return nil, errors.New("cache entity tag not found")
		}
		ocp := otag2.Property.(*types.CacheProperty)

		from, err := c.db.FindEntityById(ctx, scp.RefID)
		if err != nil || from == nil {
			return nil, errors.New("source entity not found in database")
		}

		to, err := c.db.FindEntityById(ctx, ocp.RefID)
		if err != nil || to == nil {
			return nil, errors.New("destination entity not found in database")
		}

		newedge, err := c.db.CreateEdge(ctx, &types.Edge{
			CreatedAt:  edge.CreatedAt,
			LastSeen:   edge.LastSeen,
			Relation:   e.Relation,
			FromEntity: from,
			ToEntity:   to,
		})
		if err != nil || newedge == nil {
			return nil, err
		}
		_ = c.createCacheEdgeTag(e, "cache_create_edge", newedge.ID, time.Now())
	}

	return e, err
}

// FindEdgeById implements the Repository interface.
func (c *Cache) FindEdgeById(ctx context.Context, id string) (*types.Edge, error) {
	return c.cache.FindEdgeById(ctx, id)
}

// IncomingEdges implements the Repository interface.
func (c *Cache) IncomingEdges(ctx context.Context, entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	var refID string
	var dbquery, found bool

	if since.IsZero() || since.Before(c.start) {
		if tag, ts, _ := c.checkCacheEntityTag(entity, "cache_incoming_edges"); tag == nil {
			dbquery = true
		} else if since.Before(ts) {
			found = true
			dbquery = true
			refID = tag.Property.(*types.CacheProperty).RefID
		}
	}

	if dbquery {
		if !found {
			tag, _, _ := c.checkCacheEntityTag(entity, "cache_create_entity")
			if tag == nil {
				return nil, errors.New("cache entity tag not found")
			}
			refID = tag.Property.(*types.CacheProperty).RefID
		}

		_ = c.createCacheEntityTag(entity, "cache_incoming_edges", refID, since)

		if dbedges, dberr := c.db.IncomingEdges(ctx, &types.Entity{ID: refID}, since); dberr == nil && len(dbedges) > 0 {
			for _, edge := range dbedges {
				e, err := c.db.FindEntityById(ctx, edge.FromEntity.ID)
				if err != nil || e == nil {
					continue
				}
				edge.FromEntity = e

				if e, err := c.cache.CreateEntity(ctx, &types.Entity{
					CreatedAt: edge.FromEntity.CreatedAt,
					LastSeen:  edge.FromEntity.LastSeen,
					Asset:     edge.FromEntity.Asset,
				}); err == nil && e != nil {
					_ = c.createCacheEntityTag(e, "cache_create_entity", edge.FromEntity.ID, time.Now())

					if newedge, err := c.cache.CreateEdge(ctx, &types.Edge{
						CreatedAt:  edge.CreatedAt,
						LastSeen:   edge.LastSeen,
						Relation:   edge.Relation,
						FromEntity: e,
						ToEntity:   entity,
					}); err == nil && newedge != nil {
						_ = c.createCacheEdgeTag(newedge, "cache_create_edge", edge.ID, time.Now())
					}
				}
			}
		}
	}

	return c.cache.IncomingEdges(ctx, entity, since, labels...)
}

// OutgoingEdges implements the Repository interface.
func (c *Cache) OutgoingEdges(ctx context.Context, entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	var refID string
	var dbquery, found bool

	if since.IsZero() || since.Before(c.start) {
		if tag, ts, _ := c.checkCacheEntityTag(entity, "cache_outgoing_edges"); !found {
			dbquery = true
		} else if since.Before(ts) {
			found = true
			dbquery = true
			refID = tag.Property.(*types.CacheProperty).RefID
		}
	}

	if dbquery {
		if !found {
			tag, _, _ := c.checkCacheEntityTag(entity, "cache_create_entity")
			if tag == nil {
				return nil, errors.New("cache entity tag not found")
			}
			refID = tag.Property.(*types.CacheProperty).RefID
		}

		_ = c.createCacheEntityTag(entity, "cache_outgoing_edges", refID, since)

		if dbedges, dberr := c.db.OutgoingEdges(ctx, &types.Entity{ID: refID}, since); dberr == nil && len(dbedges) > 0 {
			for _, edge := range dbedges {
				e, err := c.db.FindEntityById(ctx, edge.ToEntity.ID)
				if err != nil || e == nil {
					continue
				}
				edge.ToEntity = e

				if e, err := c.cache.CreateEntity(ctx, &types.Entity{
					CreatedAt: edge.ToEntity.CreatedAt,
					LastSeen:  edge.ToEntity.LastSeen,
					Asset:     edge.ToEntity.Asset,
				}); err == nil && e != nil {
					_ = c.createCacheEntityTag(e, "cache_create_entity", edge.ToEntity.ID, time.Now())

					if newedge, err := c.cache.CreateEdge(ctx, &types.Edge{
						CreatedAt:  edge.CreatedAt,
						LastSeen:   edge.LastSeen,
						Relation:   edge.Relation,
						FromEntity: entity,
						ToEntity:   e,
					}); err == nil && newedge != nil {
						_ = c.createCacheEdgeTag(newedge, "cache_create_edge", edge.ID, time.Now())
					}
				}
			}
		}
	}

	return c.cache.OutgoingEdges(ctx, entity, since, labels...)
}

// DeleteEdge implements the Repository interface.
func (c *Cache) DeleteEdge(ctx context.Context, id string) error {
	tag, _, _ := c.checkCacheEdgeTag(&types.Edge{ID: id}, "cache_create_edge")
	if tag == nil {
		return errors.New("cache edge tag not found")
	}
	cp := tag.Property.(*types.CacheProperty)

	if err := c.db.DeleteEdge(ctx, cp.RefID); err != nil {
		return err
	}
	return c.cache.DeleteEdge(ctx, id)
}
