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
	oam "github.com/owasp-amass/open-asset-model"
)

// CoKeyedGroups implements repository.CoKeyedGrouper: it groups entities of
// atype that share a blocking key in the graph, so a duplicate sweep never
// loads the whole type. It returns the groups of 2..maxGroup members (a key
// shared by more than maxGroup entities is too common to discriminate and is
// dropped); since, when non-zero, limits to keys whose backing edge, node, or
// tag was last seen at or after it.
func (neo *NeoRepository) CoKeyedGroups(ctx context.Context, atype oam.AssetType, key types.CoKey,
	param string, maxGroup int, since time.Time) ([]types.CoKeyGroup, error) {
	if neo == nil || neo.DB == nil {
		return nil, errors.New("missing Neo4j reader")
	}
	if maxGroup < 2 {
		return nil, errors.New("maxGroup must be at least 2")
	}

	// The asset type becomes a node label, which cannot be a parameter, so it is
	// validated against OAM's asset types. The "id" and "organization" edges are
	// stored as the uppercased relationship types ID and ORGANIZATION.
	label, err := assetLabel(atype)
	if err != nil {
		return nil, err
	}

	params := map[string]any{"max": maxGroup}
	sinceOK := !since.IsZero()
	if sinceOK {
		params["since"] = timeToNeo4jTime(since)
	}

	var query string
	switch key {
	case types.CoKeyIdentifier:
		edgeWhere := ""
		if sinceOK {
			edgeWhere = " WHERE r.updated_at >= $since"
		}
		query = "MATCH (a:Entity:" + label + ")-[r:ID]->(k:Entity)" + edgeWhere +
			" WITH k.entity_id AS key, collect(DISTINCT a.entity_id) AS ids" +
			" WHERE size(ids) >= 2 AND size(ids) <= $max RETURN key AS k, ids"
	case types.CoKeyContactRecord:
		edgeWhere := ""
		if sinceOK {
			edgeWhere = " WHERE r.updated_at >= $since"
		}
		query = "MATCH (a:Entity:" + label + ")<-[r:ORGANIZATION]-(k:Entity)" + edgeWhere +
			" WITH k.entity_id AS key, collect(DISTINCT a.entity_id) AS ids" +
			" WHERE size(ids) >= 2 AND size(ids) <= $max RETURN key AS k, ids"
	case types.CoKeyLocation:
		// Address edges are stored as the uppercased relationship types.
		edgeWhere := " WHERE type(r) IN ['LEGAL_ADDRESS', 'HQ_ADDRESS', 'LOCATION']"
		if sinceOK {
			edgeWhere += " AND r.updated_at >= $since"
		}
		query = "MATCH (a:Entity:" + label + ")-[r]->(k:Entity)" + edgeWhere +
			" WITH k.entity_id AS key, collect(DISTINCT a.entity_id) AS ids" +
			" WHERE size(ids) >= 2 AND size(ids) <= $max RETURN key AS k, ids"
	case types.CoKeyRegistration:
		where := "trim(coalesce(a.jurisdiction, '')) <> '' AND trim(coalesce(a.registration_id, '')) <> ''"
		if sinceOK {
			where += " AND a.updated_at >= $since"
		}
		// jurisdiction upper+trim, registration_id upper with whitespace removed.
		// The escape sequences are written so the Cypher text carries \t, \n and
		// \r (which Cypher interprets), not raw control characters.
		keyExpr := `toUpper(trim(a.jurisdiction)) + '|' + ` +
			`toUpper(replace(replace(replace(replace(a.registration_id, ' ', ''), '\t', ''), '\n', ''), '\r', ''))`
		query = "MATCH (a:Entity:" + label + ") WHERE " + where +
			" WITH " + keyExpr + " AS key, collect(DISTINCT a.entity_id) AS ids" +
			" WHERE size(ids) >= 2 AND size(ids) <= $max RETURN key AS k, ids"
	case types.CoKeyTag:
		if param == "" {
			return nil, errors.New("tag property name required for CoKeyTag")
		}
		params["param"] = param
		tagWhere := ""
		if sinceOK {
			tagWhere = " WHERE p.updated_at >= $since"
		}
		query = "MATCH (p:EntityTag {property_name: $param})" + tagWhere +
			" MATCH (a:Entity:" + label + " {entity_id: p.entity_id})" +
			" WITH p.property_value AS key, collect(DISTINCT a.entity_id) AS ids" +
			" WHERE size(ids) >= 2 AND size(ids) <= $max RETURN key AS k, ids"
	default:
		return nil, fmt.Errorf("unknown CoKey %d", key)
	}

	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB, query, params,
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}

	groups := make([]types.CoKeyGroup, 0, len(result.Records))
	for _, record := range result.Records {
		k, _, err := neo4jdb.GetRecordValue[string](record, "k")
		if err != nil {
			return nil, err
		}
		raw, isnil, err := neo4jdb.GetRecordValue[[]any](record, "ids")
		if err != nil {
			return nil, err
		}
		if isnil {
			continue
		}

		ids := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				ids = append(ids, s)
			}
		}
		groups = append(groups, types.CoKeyGroup{Key: k, IDs: ids})
	}

	return groups, nil
}
