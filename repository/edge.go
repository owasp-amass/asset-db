// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"gorm.io/gorm"
)

// DeleteEdge removes an edge in the database by its ID.
// It takes a string representing the edge ID and removes the corresponding edge from the database.
// Returns an error if the edge is not found.
func (sql *sqlRepository) DeleteEdge(id string) error {
	relId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}
	return sql.deleteEdges([]uint64{relId})
}

// deleteEdges removes all rows in the Edges table with primary keys in the provided slice.
func (sql *sqlRepository) deleteEdges(ids []uint64) error {
	return sql.db.Exec("DELETE FROM edges WHERE edge_id IN ?", ids).Error
}

// Link creates an edge between two entities in the database.
// The edge is established by creating a new Edge in the database, linking the two entities.
// Returns the created edge as a types.Edge or an error if the link creation fails.
func (sql *sqlRepository) Link(edge *types.Edge) (*types.Edge, error) {
	if edge == nil || edge.Relation == nil || edge.FromEntity == nil ||
		edge.FromEntity.Asset == nil || edge.ToEntity == nil || edge.ToEntity.Asset == nil {
		return &types.Edge{}, errors.New("failed input validation checks")
	}

	if !oam.ValidRelationship(edge.FromEntity.Asset.AssetType(),
		edge.Relation.Label(), edge.Relation.RelationType(), edge.ToEntity.Asset.AssetType()) {
		return &types.Edge{}, fmt.Errorf("%s -%s-> %s is not valid in the taxonomy",
			edge.FromEntity.Asset.AssetType(), edge.Relation.Label(), edge.ToEntity.Asset.AssetType())
	}

	// ensure that duplicate relationships are not entered into the database
	if e, found := sql.isDuplicateEdge(edge); found {
		return e, nil
	}

	fromEntityId, err := strconv.ParseUint(edge.FromEntity.ID, 10, 64)
	if err != nil {
		return &types.Edge{}, err
	}

	toEntityId, err := strconv.ParseUint(edge.ToEntity.ID, 10, 64)
	if err != nil {
		return &types.Edge{}, err
	}

	jsonContent, err := edge.Relation.JSON()
	if err != nil {
		return &types.Edge{}, err
	}

	r := Edge{
		Type:         string(edge.Relation.RelationType()),
		Content:      jsonContent,
		FromEntityID: fromEntityId,
		ToEntityID:   toEntityId,
	}

	result := sql.db.Create(&r)
	if result.Error != nil {
		return &types.Edge{}, result.Error
	}
	return toEdge(r), nil
}

// isDuplicateEdge checks if the relationship between source and dest already exists.
func (sql *sqlRepository) isDuplicateEdge(edge *types.Edge) (*types.Edge, bool) {
	var dup bool
	var e *types.Edge

	if outs, err := sql.OutgoingEdges(edge.FromEntity, time.Time{}, edge.Relation.Label()); err == nil {
		for _, out := range outs {
			if edge.ToEntity.ID == out.ToEntity.ID {
				_ = sql.edgeSeen(out)
				e, err = sql.edgeById(out.ID)
				if err != nil {
					log.Println("[ERROR] failed when re-retrieving the edge", err)
					return nil, false
				}
				dup = true
				break
			}
		}
	}
	return e, dup
}

// edgeSeen updates the last seen timestamp for the specified edge.
func (sql *sqlRepository) edgeSeen(rel *types.Edge) error {
	id, err := strconv.ParseInt(rel.ID, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to update last seen for ID %s could not parse id; err: %w", rel.ID, err)
	}

	result := sql.db.Exec("UPDATE edges SET last_seen = current_timestamp WHERE edge_id = ?", id)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// IncomingEdges finds all edges pointing to the entity of the specified labels and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no labels are specified, all incoming eges are returned.
func (sql *sqlRepository) IncomingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	entityId, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	var edges []Edge
	var result *gorm.DB
	if since.IsZero() {
		result = sql.db.Where("to_entity_id = ?", entityId).Find(&edges)
	} else {
		result = sql.db.Where("to_entity_id = ? AND last_seen > ?", entityId, since).Find(&edges)
	}
	if err := result.Error; err != nil {
		return nil, err
	}

	var results []Edge
	if len(labels) > 0 {
		for _, edge := range edges {
			e := &edge

			if rel, err := e.Parse(); err == nil {
				for _, label := range labels {
					if label == rel.Label() {
						results = append(results, edge)
						break
					}
				}
			}
		}
	} else {
		results = edges
	}

	return toEdges(results), nil
}

// OutgoingEdges finds all edges from the entity of the specified labels and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no labels are specified, all outgoing edges are returned.
func (sql *sqlRepository) OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	entityId, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	var edges []Edge
	var result *gorm.DB
	if since.IsZero() {
		result = sql.db.Where("from_entity_id = ?", entityId).Find(&edges)
	} else {
		result = sql.db.Where("from_entity_id = ? AND last_seen > ?", entityId, since).Find(&edges)
	}
	if err := result.Error; err != nil {
		return nil, err
	}

	var results []Edge
	if len(labels) > 0 {
		for _, edge := range edges {
			e := &edge

			if rel, err := e.Parse(); err == nil {
				for _, label := range labels {
					if label == rel.Label() {
						results = append(results, edge)
						break
					}
				}
			}
		}
	} else {
		results = edges
	}

	return toEdges(results), nil
}

func (sql *sqlRepository) edgeById(id string) (*types.Edge, error) {
	var rel Edge

	result := sql.db.Where("edge_id = ?", id).First(&rel)
	if result.Error != nil {
		return nil, result.Error
	}
	return toEdge(rel), nil
}

// toEdge converts a database Edge to a types.Edge.
func toEdge(r Edge) *types.Edge {
	e := &r
	rel, err := e.Parse()
	if err != nil {
		return nil
	}

	edge := &types.Edge{
		ID:        strconv.FormatUint(r.ID, 10),
		CreatedAt: r.CreatedAt,
		LastSeen:  r.LastSeen,
		Relation:  rel,
		FromEntity: &types.Entity{
			ID: strconv.FormatUint(r.FromEntityID, 10),
			// Not joining to Asset to get Content
		},
		ToEntity: &types.Entity{
			ID: strconv.FormatUint(r.ToEntityID, 10),
			// Not joining to Asset to get Content
		},
	}
	return edge
}

// toEdges converts a slice of database Edges to a slice of types.Edge structs.
func toEdges(edges []Edge) []*types.Edge {
	var res []*types.Edge

	for _, r := range edges {
		if e := toEdge(r); e != nil {
			res = append(res, e)
		}
	}
	return res
}
