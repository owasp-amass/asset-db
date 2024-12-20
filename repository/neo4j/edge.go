// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
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
func (neo *neoRepository) CreateEdge(edge *types.Edge) (*types.Edge, error) {
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
	if e, found := neo.isDuplicateEdge(edge, updated); found {
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
func (neo *neoRepository) isDuplicateEdge(edge *types.Edge, updated time.Time) (*types.Edge, bool) {
	var dup bool
	var e *types.Edge

	if outs, err := neo.OutgoingEdges(edge.FromEntity, time.Time{}, edge.Relation.Label()); err == nil {
		for _, out := range outs {
			if edge.ToEntity.ID == out.ToEntity.ID && reflect.DeepEqual(edge.Relation, out.Relation) {
				_ = neo.edgeSeen(out, updated)

				e, err = neo.FindEdgeById(out.ID)
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
func (neo *neoRepository) edgeSeen(rel *types.Edge, updated time.Time) error {
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

func (neo *neoRepository) FindEdgeById(id string) (*types.Edge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db,
		"MATCH (from:Entity)-[r]->(to:Entity) WHERE r.elementId = $eid RETURN r, from.entity_id AS fid, to.entity_id AS tid",
		map[string]interface{}{
			"eid": id,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)

	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, errors.New("no edge was found")
	}

	r, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Relationship](result.Records[0], "r")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the relationship is nil")
	}

	fid, isnil, err := neo4jdb.GetRecordValue[string](result.Records[0], "fid")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the from entity ID is nil")
	}

	tid, isnil, err := neo4jdb.GetRecordValue[string](result.Records[0], "tid")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the to entity ID is nil")
	}

	edge, err := relationshipToEdge(r)
	if err != nil {
		return nil, err
	}
	edge.FromEntity = &types.Entity{ID: fid}
	edge.ToEntity = &types.Entity{ID: tid}
	return edge, err
}

// IncomingEdges finds all edges pointing to the entity of the specified labels and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no labels are specified, all incoming eges are returned.
func (neo *neoRepository) IncomingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
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
func (neo *neoRepository) OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
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
func (neo *neoRepository) DeleteEdge(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := neo4jdb.ExecuteQuery(ctx, neo.db,
		"MATCH ()-[r]->() WHERE r.elementId = $eid DELETE r",
		map[string]interface{}{
			"eid": id,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)

	return err
}
