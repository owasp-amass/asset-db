// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlrepo

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"gorm.io/gorm"
)

// CreateEdge creates an edge between two entities in the database.
// The edge is established by creating a new Edge in the database, linking the two entities.
// Returns the created edge as a types.Edge or an error if the link creation fails.
func (sql *sqlRepository) CreateEdge(edge *types.Edge) (*types.Edge, error) {
	if edge == nil || edge.Relation == nil || edge.FromEntity == nil ||
		edge.FromEntity.Asset == nil || edge.ToEntity == nil || edge.ToEntity.Asset == nil {
		return nil, errors.New("failed input validation checks")
	}

	if !oam.ValidRelationship(edge.FromEntity.Asset.AssetType(),
		edge.Relation.Label(), edge.Relation.RelationType(), edge.ToEntity.Asset.AssetType()) {
		return &types.Edge{}, fmt.Errorf("%s -%s-> %s is not valid in the taxonomy",
			edge.FromEntity.Asset.AssetType(), edge.Relation.Label(), edge.ToEntity.Asset.AssetType())
	}

	var updated time.Time
	if edge.LastSeen.IsZero() {
		updated = time.Now().UTC()
	} else {
		updated = edge.LastSeen.UTC()
	}
	// ensure that duplicate relationships are not entered into the database
	if e, found := sql.isDuplicateEdge(edge, updated); found {
		return e, nil
	}

	fromEntityId, err := strconv.ParseUint(edge.FromEntity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	toEntityId, err := strconv.ParseUint(edge.ToEntity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	jsonContent, err := edge.Relation.JSON()
	if err != nil {
		return nil, err
	}

	r := Edge{
		Type:         string(edge.Relation.RelationType()),
		Content:      jsonContent,
		FromEntityID: fromEntityId,
		ToEntityID:   toEntityId,
		UpdatedAt:    updated,
	}
	if edge.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	} else {
		r.CreatedAt = edge.CreatedAt.UTC()
	}

	result := sql.db.Create(&r)
	if err := result.Error; err != nil {
		return nil, err
	}
	return toEdge(r), nil
}

// isDuplicateEdge checks if the relationship between source and dest already exists.
func (sql *sqlRepository) isDuplicateEdge(edge *types.Edge, updated time.Time) (*types.Edge, bool) {
	var dup bool
	var e *types.Edge

	if outs, err := sql.OutgoingEdges(edge.FromEntity, time.Time{}, edge.Relation.Label()); err == nil {
		for _, out := range outs {
			if edge.ToEntity.ID == out.ToEntity.ID && reflect.DeepEqual(edge.Relation, out.Relation) {
				_ = sql.edgeSeen(out, updated)

				e, err = sql.FindEdgeById(out.ID)
				if err != nil {
					return nil, false
				}

				dup = true
				break
			}
		}
	}
	return e, dup
}

// edgeSeen updates the updated_at timestamp for the specified edge.
func (sql *sqlRepository) edgeSeen(rel *types.Edge, updated time.Time) error {
	id, err := strconv.ParseUint(rel.ID, 10, 64)
	if err != nil {
		return err
	}

	jsonContent, err := rel.Relation.JSON()
	if err != nil {
		return err
	}

	fromEntityId, err := strconv.ParseUint(rel.FromEntity.ID, 10, 64)
	if err != nil {
		return err
	}

	toEntityId, err := strconv.ParseUint(rel.ToEntity.ID, 10, 64)
	if err != nil {
		return err
	}

	r := Edge{
		ID:           id,
		Type:         string(rel.Relation.RelationType()),
		Content:      jsonContent,
		FromEntityID: fromEntityId,
		ToEntityID:   toEntityId,
		CreatedAt:    rel.CreatedAt,
		UpdatedAt:    updated,
	}

	result := sql.db.Save(&r)
	if err := result.Error; err != nil {
		return err
	}
	return nil
}

func (sql *sqlRepository) FindEdgeById(id string) (*types.Edge, error) {
	var rel Edge

	result := sql.db.Where("edge_id = ?", id).First(&rel)
	if err := result.Error; err != nil {
		return nil, err
	}

	return toEdge(rel), nil
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
		result = sql.db.Where("to_entity_id = ? AND updated_at >= ?", entityId, since.UTC()).Find(&edges)
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

	if len(results) == 0 {
		return nil, errors.New("zero edges found")
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
		result = sql.db.Where("from_entity_id = ? AND updated_at >= ?", entityId, since.UTC()).Find(&edges)
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

	if len(results) == 0 {
		return nil, errors.New("zero edges found")
	}
	return toEdges(results), nil
}

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

// toEdge converts a database Edge to a types.Edge.
func toEdge(r Edge) *types.Edge {
	e := &r
	rel, err := e.Parse()
	if err != nil {
		return nil
	}

	return &types.Edge{
		ID:        strconv.FormatUint(r.ID, 10),
		CreatedAt: r.CreatedAt.In(time.UTC).Local(),
		LastSeen:  r.UpdatedAt.In(time.UTC).Local(),
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
