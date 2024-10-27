// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
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
// It takes the source entity, the edge, and destination entity as inputs.
// The edge is established by creating a new Edge struct in the database, linking the two entities.
// Returns the created edge as a types.Edge or an error if the link creation fails.
func (sql *sqlRepository) Link(source *types.Entity, edge *types.Edge, destination *types.Entity) (*types.Edge, error) {
	// check that this link will create a valid relationship within the taxonomy
	srctype := source.Asset.AssetType()
	destype := destination.Asset.AssetType()
	if !oam.ValidRelationship(srctype, edge, destype) {
		return &types.Edge{}, fmt.Errorf("%s -%s-> %s is not valid in the taxonomy", srctype, edge, destype)
	}

	// ensure that duplicate relationships are not entered into the database
	if rel, found := sql.isDuplicateEdge(source, edge, destination); found {
		return rel, nil
	}

	fromEntityId, err := strconv.ParseUint(source.ID, 10, 64)
	if err != nil {
		return &types.Edge{}, err
	}

	toEntityId, err := strconv.ParseUint(destination.ID, 10, 64)
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
func (sql *sqlRepository) isDuplicateEdge(source *types.Entity, edge *types.Edge, dest *types.Entity) (*types.Edge, bool) {
	var dup bool
	var rel *types.Edge

	if outs, err := sql.OutgoingEdges(source, time.Time{}, edge.Relation.Label()); err == nil {
		for _, out := range outs {
			if dest.ID == out.ToEntity.ID {
				_ = sql.edgeSeen(out)
				rel, err = sql.edgeById(out.ID)
				if err != nil {
					log.Println("[ERROR] failed when re-retrieving relation", err)
					return nil, false
				}
				dup = true
				break
			}
		}
	}
	return rel, dup
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

// IncomingEdges finds all edges pointing to the entity of the specified relation types and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no relationTypes are specified, all outgoing eges are returned.
func (sql *sqlRepository) IncomingEdges(entity *types.Entity, since time.Time, relationTypes ...string) ([]*types.Edge, error) {
	entityId, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	edges := []Edge{}
	if len(relationTypes) > 0 {
		res := sql.db.Where("to_entity_id = ? AND etype IN ?", entityId, relationTypes).Find(&edges)
		if res.Error != nil {
			return nil, res.Error
		}
	} else {
		res := sql.db.Where("to_entity_id = ?", entityId).Find(&edges)
		if res.Error != nil {
			return nil, res.Error
		}
	}

	return toEdges(edges), nil
}

// OutgoingEdges finds all edges from the entity of the specified relation types and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no relationTypes are specified, all outgoing edges are returned.
func (sql *sqlRepository) OutgoingEdges(entity *types.Entity, since time.Time, relationTypes ...string) ([]*types.Edge, error) {
	entityId, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	edges := []Edge{}
	if len(relationTypes) > 0 {
		res := sql.db.Where("from_entity_id = ? AND etype IN ?", entityId, relationTypes).Find(&edges)
		if res.Error != nil {
			return nil, res.Error
		}
	} else {
		res := sql.db.Where("from_entity_id = ?", entityId).Find(&edges)
		if res.Error != nil {
			return nil, res.Error
		}
	}

	return toEdges(edges), nil
}

func (sql *sqlRepository) edgeById(id string) (*types.Edge, error) {
	rel := Edge{}

	result := sql.db.Where("edge_id = ?", id).First(&rel)
	if result.Error != nil {
		return nil, result.Error
	}

	return toEdge(rel), nil
}

// toEdge converts a database Edge to a types.Edge.
func toEdge(r Edge) *types.Edge {
	rel := &types.Edge{
		ID:       strconv.FormatUint(r.ID, 10),
		Type:     r.Type,
		LastSeen: r.LastSeen,
		FromEntity: &types.Entity{
			ID: strconv.FormatUint(r.FromEntityID, 10),
			// Not joining to Asset to get Content
		},
		ToEntity: &types.Entity{
			ID: strconv.FormatUint(r.ToEntityID, 10),
			// Not joining to Asset to get Content
		},
	}
	return rel
}

// toEdges converts a slice of database Edges to a slice of types.Edge structs.
func toEdges(edges []Edge) []*types.Edge {
	var res []*types.Edge

	for _, r := range edges {
		res = append(res, toEdge(r))
	}
	return res
}
