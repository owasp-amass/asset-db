// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
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

	if edge.LastSeen.IsZero() {
		edge.LastSeen = time.Now()
	}
	// ensure that duplicate relationships are not entered into the database
	if e, found := neo.isDuplicateEdge(edge, edge.LastSeen); found {
		return e, nil
	}

	if edge.CreatedAt.IsZero() {
		edge.CreatedAt = time.Now()
	}

	props, err := edgePropsMap(edge)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	from := fmt.Sprintf("MATCH (from:Entity {entity_id: '%s'})", edge.FromEntity.ID)
	to := fmt.Sprintf("MATCH (to:Entity {entity_id: '%s'})", edge.ToEntity.ID)
	query := fmt.Sprintf("%s %s CREATE (from)-[r:%s $props]->(to) RETURN r", from, to, strings.ToUpper(edge.Relation.Label()))
	result, err := neo4jdb.ExecuteQuery(ctx, neo.db, query,
		map[string]interface{}{"props": props},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, errors.New("no records returned from the query")
	}

	rel, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Relationship](result.Records[0], "r")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the relationship is nil")
	}

	r, err := relationshipToEdge(rel)
	if err != nil {
		return nil, err
	}
	r.FromEntity = edge.FromEntity
	r.ToEntity = edge.ToEntity

	return r, nil
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := fmt.Sprintf("MATCH ()-[r]->() WHERE elementId(r) = $eid SET r.updated_at = localDateTime('%s')", timeToNeo4jTime(updated))
	_, err := neo4jdb.ExecuteQuery(ctx, neo.db, query,
		map[string]interface{}{
			"eid": rel.ID,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	return err
}

func (neo *neoRepository) FindEdgeById(id string) (*types.Edge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db,
		"MATCH (from:Entity)-[r]->(to:Entity) WHERE elementId(r) = $eid RETURN r, from.entity_id AS fid, to.entity_id AS tid",
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := "MATCH (:Entity {entity_id: $eid})<-[r]-(from:Entity) RETURN r, from.entity_id AS fid"
	if !since.IsZero() {
		query = fmt.Sprintf("MATCH (:Entity {entity_id: $eid})<-[r]-(from:Entity) WHERE r.updated_at >= localDateTime('%s') RETURN r, from.entity_id AS fid", timeToNeo4jTime(since))
	}

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db, query,
		map[string]interface{}{
			"eid": entity.ID,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}

	var results []*types.Edge
	for _, record := range result.Records {
		r, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Relationship](record, "r")
		if err != nil {
			continue
		}
		if isnil {
			continue
		}

		if len(labels) > 0 {
			var found bool

			for _, label := range labels {
				if strings.EqualFold(label, r.Type) {
					found = true
					break
				}
			}

			if !found {
				continue
			}
		}

		fid, isnil, err := neo4jdb.GetRecordValue[string](record, "fid")
		if err != nil {
			continue
		}
		if isnil {
			continue
		}

		edge, err := relationshipToEdge(r)
		if err != nil {
			continue
		}
		edge.FromEntity = &types.Entity{ID: fid}
		edge.ToEntity = entity
		results = append(results, edge)
	}

	if len(results) == 0 {
		return nil, errors.New("zero edges found")
	}
	return results, nil
}

// OutgoingEdges finds all edges from the entity of the specified labels and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no labels are specified, all outgoing edges are returned.
func (neo *neoRepository) OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := "MATCH (:Entity {entity_id: $eid})-[r]->(to:Entity) RETURN r, to.entity_id AS tid"
	if !since.IsZero() {
		query = fmt.Sprintf("MATCH (:Entity {entity_id: $eid})-[r]->(to:Entity) WHERE r.updated_at >= localDateTime('%s') RETURN r, to.entity_id AS tid", timeToNeo4jTime(since))
	}

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db, query,
		map[string]interface{}{
			"eid": entity.ID,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}

	var results []*types.Edge
	for _, record := range result.Records {
		r, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Relationship](record, "r")
		if err != nil {
			continue
		}
		if isnil {
			continue
		}

		if len(labels) > 0 {
			var found bool

			for _, label := range labels {
				if strings.EqualFold(label, r.Type) {
					found = true
					break
				}
			}

			if !found {
				continue
			}
		}

		tid, isnil, err := neo4jdb.GetRecordValue[string](record, "tid")
		if err != nil {
			continue
		}
		if isnil {
			continue
		}

		edge, err := relationshipToEdge(r)
		if err != nil {
			continue
		}
		edge.FromEntity = entity
		edge.ToEntity = &types.Entity{ID: tid}
		results = append(results, edge)
	}

	if len(results) == 0 {
		return nil, errors.New("zero edges found")
	}
	return results, nil
}

// DeleteEdge removes an edge in the database by its ID.
// It takes a string representing the edge ID and removes the corresponding edge from the database.
// Returns an error if the edge is not found.
func (neo *neoRepository) DeleteEdge(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := neo4jdb.ExecuteQuery(ctx, neo.db,
		"MATCH ()-[r]->() WHERE elementId(r) = $eid DELETE r",
		map[string]interface{}{
			"eid": id,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)

	return err
}
