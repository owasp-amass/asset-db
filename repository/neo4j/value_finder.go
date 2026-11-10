// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/internal/valuequery"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// FindEntitiesByTagValue implements repository.ValueFinder. A tag's value is
// its data (DNS records) or property_value (simple properties), the fields
// Property.Value returns.
func (neo *NeoRepository) FindEntitiesByTagValue(ctx context.Context, atype oam.AssetType, name, value string, contains bool, since time.Time, limit int) ([]*types.Entity, bool, error) {
	query, params, err := tagValueQuery(atype, name, value, contains, since, limit)
	if err != nil {
		return nil, false, err
	}

	return neo.entitiesByQuery(ctx, query, params, limit)
}

// tagValueQuery builds the Cypher query and parameters for
// FindEntitiesByTagValue. Every value is a parameter; the asset type label,
// which cannot be, is checked against OAM's asset types.
func tagValueQuery(atype oam.AssetType, name, value string, contains bool, since time.Time, limit int) (string, map[string]any, error) {
	if err := valuequery.Check(atype, name, value, limit); err != nil {
		return "", nil, err
	}

	label, err := assetLabel(atype)
	if err != nil {
		return "", nil, err
	}

	match := "coalesce(p.property_value, p.data) = $value"
	params := map[string]any{"name": name, "value": value, "limit": limit + 1}
	if contains {
		match = "toLower(coalesce(p.property_value, p.data)) CONTAINS $value"
		params["value"] = strings.ToLower(value)
	}
	if !since.IsZero() {
		match += " AND p.updated_at >= $since"
		params["since"] = timeToNeo4jTime(since)
	}

	query := "MATCH (p:EntityTag {property_name: $name}) WHERE " + match +
		" WITH DISTINCT p.entity_id AS eid MATCH (a:Entity:" + label + " {entity_id: eid})" +
		" RETURN a ORDER BY a.entity_id LIMIT $limit"
	return query, params, nil
}

// FindEntitiesByAttribute implements repository.ValueFinder.
func (neo *NeoRepository) FindEntitiesByAttribute(ctx context.Context, atype oam.AssetType, key, value string, since time.Time, limit int) ([]*types.Entity, bool, error) {
	query, params, err := attributeQuery(atype, key, value, since, limit)
	if err != nil {
		return nil, false, err
	}

	return neo.entitiesByQuery(ctx, query, params, limit)
}

// attributeQuery builds the Cypher query and parameters for
// FindEntitiesByAttribute; the key is a parameter too (a[$key]).
func attributeQuery(atype oam.AssetType, key, value string, since time.Time, limit int) (string, map[string]any, error) {
	if err := valuequery.Check(atype, key, value, limit); err != nil {
		return "", nil, err
	}
	if err := valuequery.CheckKey(key); err != nil {
		return "", nil, err
	}

	label, err := assetLabel(atype)
	if err != nil {
		return "", nil, err
	}

	where := "a[$key] = $value"
	params := map[string]any{"key": key, "value": value, "limit": limit + 1}
	if !since.IsZero() {
		where += " AND a.updated_at >= $since"
		params["since"] = timeToNeo4jTime(since)
	}

	return "MATCH (a:Entity:" + label + ") WHERE " + where + " RETURN a ORDER BY a.entity_id LIMIT $limit", params, nil
}

// assetLabel returns atype as a node label, accepting only OAM asset types
// because a label cannot be a query parameter.
func assetLabel(atype oam.AssetType) (string, error) {
	if !slices.Contains(oam.AssetList, atype) {
		return "", fmt.Errorf("unknown asset type %q", atype)
	}

	return string(atype), nil
}

// entitiesByQuery runs a query returning entity nodes as a, at most limit+1
// of them, and reports whether more than limit matched.
func (neo *NeoRepository) entitiesByQuery(ctx context.Context, query string, params map[string]any, limit int) ([]*types.Entity, bool, error) {
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB, query, params,
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, false, err
	}

	more := len(result.Records) > limit
	records := result.Records
	if more {
		records = records[:limit]
	}

	out := make([]*types.Entity, 0, len(records))
	for _, record := range records {
		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](record, "a")
		if err != nil {
			return nil, false, err
		}
		if isnil {
			return nil, false, errors.New("the record value for the node is nil")
		}

		ent, err := nodeToEntity(node)
		if err != nil {
			return nil, false, err
		}

		out = append(out, ent)
	}

	return out, more, nil
}
