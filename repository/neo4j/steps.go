// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"errors"
	"fmt"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
)

// ReadSteps returns, each once, the edges whose source is one of ids and that
// a forward step matches, and those whose destination is one of ids and that
// a backward step matches, in one query, with no limit per entity. A port
// relation is stored under its own name (tcp_port_443) and matches the label
// "port".
func (neo *NeoRepository) ReadSteps(ctx context.Context, ids []string, steps []types.Step, since time.Time) ([]*types.Edge, error) {
	if neo == nil || neo.DB == nil {
		return nil, errors.New("missing Neo4j repository")
	}
	if len(ids) > MaxEntitiesByIds {
		return nil, fmt.Errorf("at most %d entity IDs may be read at once", MaxEntitiesByIds)
	}
	forward, backward, err := types.CheckSteps(steps)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}

	keys := make([]any, 0, len(forward)+len(backward))
	for _, s := range append(forward, backward...) {
		keys = append(keys, []any{s.FromType, s.Label, s.RelationType, s.ToType, s.Forward})
	}
	params := map[string]any{"ids": ids, "steps": keys}
	seen := ""
	if !since.IsZero() {
		params["since"] = timeToNeo4jTime(since)
		seen = " AND r.updated_at >= $since"
	}

	query := `UNWIND $ids AS eid
MATCH (n:Entity {entity_id: eid})-[r]-(:Entity)
WITH n, r, startNode(r) AS f, endNode(r) AS t
WITH r, f, t, [toLower(f.etype),
    CASE WHEN r.etype = 'PortRelation' THEN 'port' ELSE toLower(type(r)) END,
    toLower(r.etype), toLower(t.etype), f = n] AS step
WHERE step IN $steps` + seen + `
RETURN DISTINCT r, f.entity_id AS fid, t.entity_id AS tid`

	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB, query, params, neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname))
	if err != nil {
		return nil, err
	}

	out := make([]*types.Edge, 0, len(result.Records))
	for _, record := range result.Records {
		r, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Relationship](record, "r")
		if err != nil || isnil {
			return nil, errors.New("malformed Neo4j relationship")
		}

		fid, _, err := neo4jdb.GetRecordValue[string](record, "fid")
		if err != nil {
			return nil, err
		}

		tid, _, err := neo4jdb.GetRecordValue[string](record, "tid")
		if err != nil {
			return nil, err
		}

		edge, err := relationshipToEdge(r)
		if err != nil {
			return nil, err
		}

		edge.FromEntity = &types.Entity{ID: fid}
		edge.ToEntity = &types.Entity{ID: tid}
		out = append(out, edge)
	}

	return out, nil
}
