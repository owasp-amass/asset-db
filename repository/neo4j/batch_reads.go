// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
)

// MaxEntitiesByIds is the most IDs FindEntitiesByIds reads at once.
const MaxEntitiesByIds = 1000

// MaxEdgeLabelsPerRead is the most labels ReadEdgesPerLabel filters by.
const MaxEdgeLabelsPerRead = 64

// FindEntitiesByIds returns the entities with the given IDs, with their
// assets, in the order of ids, in one query. An ID with no entity is left
// out.
func (neo *NeoRepository) FindEntitiesByIds(ctx context.Context, ids []string) ([]*types.Entity, error) {
	if neo == nil || neo.DB == nil {
		return nil, errors.New("missing Neo4j repository")
	}
	if len(ids) > MaxEntitiesByIds {
		return nil, fmt.Errorf("at most %d entity IDs may be read at once", MaxEntitiesByIds)
	}
	if len(ids) == 0 {
		return nil, nil
	}

	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB,
		"MATCH (a:Entity) WHERE a.entity_id IN $ids RETURN a",
		map[string]any{"ids": ids},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}

	found := make(map[string]*types.Entity, len(result.Records))
	for _, record := range result.Records {
		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](record, "a")
		if err != nil {
			return nil, err
		}
		if isnil {
			return nil, errors.New("the record value for the node is nil")
		}
		e, err := nodeToEntity(node)
		if err != nil {
			return nil, err
		}
		found[e.ID] = e
	}

	out := make([]*types.Entity, 0, len(found))
	for _, id := range ids {
		if e, ok := found[id]; ok {
			out = append(out, e)
		}
	}
	return out, nil
}

// ReadEdgesPerLabel reads an entity's edges in one direction with up to
// perLabel edges for each label (relationship type), newest first within a
// label, in one query. more lists the labels that have edges beyond
// perLabel. With no labels, every label is read.
func (neo *NeoRepository) ReadEdgesPerLabel(ctx context.Context, entity *types.Entity, direction string, since time.Time, perLabel int, labels ...string) ([]*types.Edge, []string, error) {
	if neo == nil || neo.DB == nil || entity == nil || entity.ID == "" {
		return nil, nil, errors.New("missing Neo4j repository or entity")
	}
	if perLabel < 1 || perLabel > 500 {
		return nil, nil, errors.New("edge limit per label must be 1..500")
	}
	if len(labels) > MaxEdgeLabelsPerRead {
		return nil, nil, errors.New("too many edge labels")
	}

	var pattern string
	switch direction {
	case "in":
		pattern = "(n:Entity {entity_id: $eid})<-[r]-(:Entity)"
	case "out":
		pattern = "(n:Entity {entity_id: $eid})-[r]->(:Entity)"
	case "both":
		pattern = "(n:Entity {entity_id: $eid})-[r]-(:Entity)"
	default:
		return nil, nil, errors.New("invalid edge direction")
	}

	params := map[string]any{"eid": entity.ID, "lim": int64(perLabel + 1)}
	var where []string
	if !since.IsZero() {
		params["since"] = timeToNeo4jTime(since)
		where = append(where, "r.updated_at >= $since")
	}
	if len(labels) > 0 {
		rtypes := make([]string, 0, len(labels))
		for _, l := range labels {
			if l == "" || len(l) > 128 {
				return nil, nil, errors.New("invalid edge label")
			}
			rtypes = append(rtypes, strings.ToUpper(l))
		}
		params["types"] = rtypes
		where = append(where, "type(r) IN $types")
	}

	query := "MATCH " + pattern
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += ` WITH DISTINCT r ORDER BY r.updated_at DESC, elementId(r) DESC
WITH type(r) AS t, collect(r)[0..$lim] AS rs
UNWIND range(0, size(rs) - 1) AS i
WITH t, i, rs[i] AS r
RETURN t, i, r, startNode(r).entity_id AS fid, endNode(r).entity_id AS tid ORDER BY t, i`

	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB, query, params, neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname))
	if err != nil {
		return nil, nil, err
	}

	var out []*types.Edge
	var more []string
	for _, record := range result.Records {
		t, _, err := neo4jdb.GetRecordValue[string](record, "t")
		if err != nil {
			return nil, nil, err
		}
		i, _, err := neo4jdb.GetRecordValue[int64](record, "i")
		if err != nil {
			return nil, nil, err
		}
		if i >= int64(perLabel) {
			more = append(more, strings.ToLower(t))
			continue
		}

		r, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Relationship](record, "r")
		if err != nil || isnil {
			return nil, nil, errors.New("malformed Neo4j relationship")
		}
		fid, _, err := neo4jdb.GetRecordValue[string](record, "fid")
		if err != nil {
			return nil, nil, err
		}
		tid, _, err := neo4jdb.GetRecordValue[string](record, "tid")
		if err != nil {
			return nil, nil, err
		}

		edge, err := relationshipToEdge(r)
		if err != nil {
			return nil, nil, err
		}
		edge.FromEntity = &types.Entity{ID: fid}
		edge.ToEntity = &types.Entity{ID: tid}
		out = append(out, edge)
	}

	return out, more, nil
}
