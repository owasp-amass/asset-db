// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
)

// countDeletion follows a deletion in the same query: it adds one to the
// deletion count when the deletion removed something. Aggregating over no
// rows still gives one row, so the count node is always there.
const countDeletion = ` WITH count(*) AS gone
MERGE (g:GraphChange {id: 1})
SET g.deletions = coalesce(g.deletions, 0) + CASE WHEN gone > 0 THEN 1 ELSE 0 END`

// changedEntitiesQuery lists the entities changed at or after $since: their
// nodes (which hold their assets), the relationships on them, and the tags
// on them and on their relationships. Relationship times have no index, so
// this reads every relationship.
const changedEntitiesQuery = `CALL {
  MATCH (n:Entity) WHERE n.updated_at >= $since RETURN n.entity_id AS id
  UNION
  MATCH (a:Entity)-[r]->(:Entity) WHERE r.updated_at >= $since RETURN a.entity_id AS id
  UNION
  MATCH (:Entity)-[r]->(b:Entity) WHERE r.updated_at >= $since RETURN b.entity_id AS id
  UNION
  MATCH (t:EntityTag) WHERE t.updated_at >= $since RETURN t.entity_id AS id
  UNION
  MATCH (t:EdgeTag) WHERE t.updated_at >= $since
  MATCH (a:Entity)-[r]->(:Entity) WHERE elementId(r) = t.edge_id RETURN a.entity_id AS id
  UNION
  MATCH (t:EdgeTag) WHERE t.updated_at >= $since
  MATCH (:Entity)-[r]->(b:Entity) WHERE elementId(r) = t.edge_id RETURN b.entity_id AS id
}
RETURN DISTINCT id`

// GraphChanges implements repository.ChangeReader. The store's times are
// written by its clients' clocks, so Now is this client's.
func (neo *NeoRepository) GraphChanges(ctx context.Context, since time.Time) (*types.GraphChanges, error) {
	tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	out := &types.GraphChanges{Now: time.Now().UTC()}
	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB,
		"OPTIONAL MATCH (g:GraphChange {id: 1}) RETURN coalesce(g.deletions, 0) AS deletions", nil,
		neo4jdb.EagerResultTransformer, neo4jdb.ExecuteQueryWithDatabase(neo.dbname))
	if err != nil {
		return nil, err
	}
	if len(result.Records) > 0 {
		if n, _, err := neo4jdb.GetRecordValue[int64](result.Records[0], "deletions"); err == nil {
			out.Deletions = n
		}
	}
	if since.IsZero() {
		return out, nil
	}

	result, err = neo4jdb.ExecuteQuery(tctx, neo.DB, changedEntitiesQuery,
		map[string]any{"since": timeToNeo4jTime(since)},
		neo4jdb.EagerResultTransformer, neo4jdb.ExecuteQueryWithDatabase(neo.dbname))
	if err != nil {
		return nil, err
	}
	for _, record := range result.Records {
		id, isnil, err := neo4jdb.GetRecordValue[string](record, "id")
		if err != nil {
			return nil, err
		}
		if !isnil {
			out.EntityIDs = append(out.EntityIDs, id)
		}
	}

	return out, nil
}
