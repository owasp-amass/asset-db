// Copyright © by Jeff Foley 2017-2024. All rights reserved.
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
	c.Lock()
	defer c.Unlock()

	e, err := c.cache.CreateEdge(edge)
	if err != nil {
		return nil, err
	}

	sub, err := c.cache.FindEntityById(e.FromEntity.ID)
	if err != nil {
		return nil, err
	}

	obj, err := c.cache.FindEntityById(e.ToEntity.ID)
	if err != nil {
		return nil, err
	}

	if _, _, found := c.checkCacheEdgeTag(edge, "cache_create_edge"); !found {
		_ = c.createCacheEdgeTag(e, "cache_create_edge", time.Now())

		c.appendToDBQueue(func() {
			s, err := c.db.FindEntityByContent(sub.Asset, time.Time{})
			if err != nil || len(s) != 1 {
				return
			}

			o, err := c.db.FindEntityByContent(obj.Asset, time.Time{})
			if err != nil || len(o) != 1 {
				return
			}

			_, _ = c.db.CreateEdge(&types.Edge{
				CreatedAt:  edge.CreatedAt,
				LastSeen:   edge.LastSeen,
				Relation:   e.Relation,
				FromEntity: s[0],
				ToEntity:   o[0],
			})
		})
	}

	return e, nil
}

// FindEdgeById implements the Repository interface.
func (c *Cache) FindEdgeById(id string) (*types.Edge, error) {
	c.Lock()
	defer c.Unlock()

	return c.cache.FindEdgeById(id)
}

// IncomingEdges implements the Repository interface.
func (c *Cache) IncomingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	var dbquery bool

	if since.IsZero() || since.Before(c.start) {
		c.Lock()
		if tag, last, found := c.checkCacheEntityTag(entity, "cache_incoming_edges"); !found || since.Before(last) {
			dbquery = true
			if found {
				_ = c.cache.DeleteEntityTag(tag.ID)
			}
			_ = c.createCacheEntityTag(entity, "cache_incoming_edges", since)
		}
		c.Unlock()
	}

	if dbquery {
		var dberr error
		var dbedges []*types.Edge

		done := make(chan struct{}, 1)
		c.appendToDBQueue(func() {
			defer func() { done <- struct{}{} }()

			if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
				dbedges, dberr = c.db.IncomingEdges(e[0], since)

				for i, edge := range dbedges {
					if e, err := c.db.FindEntityById(edge.ToEntity.ID); err == nil && e != nil {
						dbedges[i].ToEntity = e
					}
				}
			}
		})
		<-done
		close(done)

		c.Lock()
		defer c.Unlock()

		if dberr == nil && len(dbedges) > 0 {
			for _, edge := range dbedges {
				e, err := c.cache.CreateEntity(&types.Entity{
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
	} else {
		c.Lock()
		defer c.Unlock()
	}

	return c.cache.IncomingEdges(entity, since, labels...)
}

// OutgoingEdges implements the Repository interface.
func (c *Cache) OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	var dbquery bool

	if since.IsZero() || since.Before(c.start) {
		c.Lock()
		if tag, last, found := c.checkCacheEntityTag(entity, "cache_outgoing_edges"); !found || since.Before(last) {
			dbquery = true
			if found {
				_ = c.cache.DeleteEntityTag(tag.ID)
			}
			_ = c.createCacheEntityTag(entity, "cache_outgoing_edges", since)
		}
		c.Unlock()
	}

	if dbquery {
		var dberr error
		var dbedges []*types.Edge

		done := make(chan struct{}, 1)
		c.appendToDBQueue(func() {
			defer func() { done <- struct{}{} }()

			if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
				dbedges, dberr = c.db.OutgoingEdges(e[0], since)

				for i, edge := range dbedges {
					if e, err := c.db.FindEntityById(edge.ToEntity.ID); err == nil && e != nil {
						dbedges[i].ToEntity = e
					}
				}
			}
		})
		<-done
		close(done)

		c.Lock()
		defer c.Unlock()

		if dberr == nil && len(dbedges) > 0 {
			for _, edge := range dbedges {
				e, err := c.cache.CreateEntity(&types.Entity{
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
	} else {
		c.Lock()
		defer c.Unlock()
	}

	return c.cache.OutgoingEdges(entity, since, labels...)
}

// DeleteEdge implements the Repository interface.
func (c *Cache) DeleteEdge(id string) error {
	c.Lock()
	defer c.Unlock()

	edge, err := c.cache.FindEdgeById(id)
	if err != nil {
		return nil
	}

	sub, err := c.cache.FindEntityById(edge.FromEntity.ID)
	if err != nil {
		return nil
	}

	obj, err := c.cache.FindEntityById(edge.ToEntity.ID)
	if err != nil {
		return nil
	}

	if err := c.cache.DeleteEdge(id); err != nil {
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

		edges, err := c.db.OutgoingEdges(s[0], time.Time{}, edge.Relation.Label())
		if err != nil || len(edges) == 0 {
			return
		}

		var target *types.Edge
		for _, e := range edges {
			if e.ToEntity.ID == o[0].ID && reflect.DeepEqual(e.Relation, edge.Relation) {
				target = e
				break
			}
		}
		if target != nil {
			_ = c.db.DeleteEdge(target.ID)
		}
	})

	return nil
}
