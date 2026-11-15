// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"strings"
	"testing"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
)

// hostile is a value that would end a quoted string and change a query
// written with it.
const hostile = `x' }) DETACH DELETE a //`

var since = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func TestEntitiesByContentQuery(t *testing.T) {
	query, params, err := entitiesByContentQuery(oam.FQDN, map[string]any{"name": hostile}, since, 5)
	assert.NoError(t, err, "a content query for an FQDN should build")
	assert.NotContains(t, query, hostile, "the filter value must be a parameter, not query text")
	assert.Equal(t, hostile, params["f0"], "the filter value should be the f0 parameter")
	assert.Equal(t, timeToNeo4jTime(since), params["since"], "since should be a parameter")
	assert.Equal(t, 5, params["limit"], "the limit should be a parameter")
	assert.Less(t, strings.Index(query, "RETURN"), strings.Index(query, "ORDER BY"),
		"RETURN must come before ORDER BY in Cypher")
	assert.Equal(t, "MATCH (a:Entity:FQDN) WHERE a.name = $f0 AND a.updated_at >= $since RETURN a "+
		"ORDER BY a.updated_at DESC LIMIT $limit", query, "the content query is not as expected")

	// every filter counts, in a stable order, and keeps its type
	query, params, err = entitiesByContentQuery(oam.AutonomousSystem, map[string]any{"number": 64496,
		"handle": "AS64496"}, time.Time{}, 0)
	assert.NoError(t, err, "a two-filter query should build")
	assert.Equal(t, "MATCH (a:Entity:AutonomousSystem) WHERE a.handle = $f0 AND a.number = $f1 RETURN a "+
		"ORDER BY a.updated_at DESC", query, "the two-filter query is not as expected")
	assert.Equal(t, 64496, params["f1"], "a numeric filter should keep its type")

	_, _, err = entitiesByContentQuery(oam.FQDN, map[string]any{"name) DETACH DELETE (a": "x"}, since, 0)
	assert.Error(t, err, "a filter key that is not an identifier must be refused")
	_, _, err = entitiesByContentQuery("FQDN) DETACH DELETE (a", map[string]any{"name": "x"}, since, 0)
	assert.Error(t, err, "an asset type outside OAM must be refused")
	_, _, err = entitiesByContentQuery(oam.FQDN, nil, since, 0)
	assert.Error(t, err, "a content query needs a filter")
}

func TestEntitiesByTypeQuery(t *testing.T) {
	query, params, err := entitiesByTypeQuery(oam.IPAddress, since, 10)
	assert.NoError(t, err, "a type query should build")
	assert.Equal(t, "MATCH (a:Entity:IPAddress) WHERE a.updated_at >= $since RETURN a ORDER BY a.updated_at DESC "+
		"LIMIT $limit", query, "the type query is not as expected")
	assert.Len(t, params, 2, "since and limit should be the only parameters")

	query, params, err = entitiesByTypeQuery(oam.IPAddress, time.Time{}, 0)
	assert.NoError(t, err, "a type query without bounds should build")
	assert.Equal(t, "MATCH (a:Entity:IPAddress) RETURN a ORDER BY a.updated_at DESC", query,
		"the unbounded type query is not as expected")
	assert.Empty(t, params, "an unbounded type query has no parameters")
}

func TestEdgeQueries(t *testing.T) {
	query, params, err := createEdgeQuery(hostile, "2", "dns_record", map[string]any{"name": "dns_record"})
	assert.NoError(t, err, "an edge query should build")
	assert.NotContains(t, query, hostile, "entity IDs must be parameters")
	assert.Equal(t, hostile, params["fid"], "the from ID should be a parameter")
	assert.Contains(t, query, "[r:DNS_RECORD $props]", "the relationship type should be the relation label")

	_, _, err = createEdgeQuery("1", "2", "dns_record]->() DETACH DELETE (x", nil)
	assert.Error(t, err, "a relation label that is not an identifier must be refused")

	query, params = edgeSeenQuery("5:abc:1", since)
	assert.Equal(t, "MATCH ()-[r]->() WHERE elementId(r) = $eid SET r.updated_at = $updated", query,
		"the seen query is not as expected")
	assert.Equal(t, timeToNeo4jTime(since), params["updated"], "the time should be a parameter")

	query, params = edgesQuery("7", true, since)
	assert.Equal(t, "MATCH (:Entity {entity_id: $eid})<-[r]-(from:Entity) WHERE r.updated_at >= $since "+
		"RETURN r, from.entity_id AS fid", query, "the incoming query is not as expected")
	assert.Len(t, params, 2, "the entity and since should be parameters")

	query, _ = edgesQuery("7", false, time.Time{})
	assert.Equal(t, "MATCH (:Entity {entity_id: $eid})-[r]->(to:Entity) RETURN r, to.entity_id AS tid", query,
		"the outgoing query is not as expected")
}

func TestTagQueries(t *testing.T) {
	query, params := tagsOfQuery("EntityTag", "entity_id", hostile, since)
	assert.Equal(t, "MATCH (p:EntityTag {entity_id: $id}) WHERE p.updated_at >= $since RETURN p", query,
		"the tags query is not as expected")
	assert.Equal(t, hostile, params["id"], "the entity ID should be a parameter")

	props := map[string]any{"tag_id": "t1", "created_at": "c", "updated_at": "u", "property_name": "title",
		"property_value": hostile}
	query, params, err := mergeTagQuery("EdgeTag", "edge_id", "e1", &general.SimpleProperty{PropertyName: "title",
		PropertyValue: hostile}, props)
	assert.NoError(t, err, "a simple property merge should build")
	assert.Equal(t, "MERGE (p:EdgeTag:SimpleProperty {edge_id: $owner, property_name: $i0, property_value: $i1}) "+
		"ON CREATE SET p = $props ON MATCH SET p += $seen RETURN p", query, "the simple property merge is not as expected")
	assert.Equal(t, hostile, params["i1"], "the property value should be a parameter")
	seen := params["seen"].(map[string]any)
	assert.NotContains(t, seen, "tag_id", "a stored tag keeps its id")
	assert.NotContains(t, seen, "created_at", "a stored tag keeps its first-seen time")
	assert.Equal(t, "u", seen["updated_at"], "a stored tag records the sighting")

	// a source is one tag per owner: its confidence is not part of the identity
	query, params, err = mergeTagQuery("EntityTag", "entity_id", "7", &general.SourceProperty{Source: "DNS",
		Confidence: 100}, map[string]any{})
	assert.NoError(t, err, "a source property merge should build")
	assert.Equal(t, "MERGE (p:EntityTag:SourceProperty {entity_id: $owner, name: $i0}) ON CREATE SET p = $props "+
		"ON MATCH SET p += $seen RETURN p", query, "the source property merge is not as expected")
	assert.Equal(t, "7", params["owner"], "the owner should be a parameter")

	// DNS record data was written unquoted before
	_, params, err = mergeTagQuery("EntityTag", "entity_id", "7", &dns.DNSRecordProperty{PropertyName: "dns_record",
		Data: "v=spf1 include:_spf.example.com ~all"}, map[string]any{})
	assert.NoError(t, err, "a DNS record property merge should build")
	assert.Equal(t, "v=spf1 include:_spf.example.com ~all", params["i0"], "the record data should be a parameter")

	_, _, err = mergeTagQuery("EntityTag", "entity_id", "7", nil, map[string]any{})
	assert.Error(t, err, "a nil property must be refused")
	_, _, err = mergeTagQuery("EntityTag", "entity_id) DETACH DELETE (x", "7", &general.SourceProperty{Source: "DNS"},
		map[string]any{})
	assert.Error(t, err, "an owner key that is not an identifier must be refused")

	query, _, err = createTagQuery("EntityTag", "SimpleProperty", nil)
	assert.NoError(t, err, "a tag creation query should build")
	assert.Equal(t, "CREATE (p:EntityTag:SimpleProperty $props) RETURN p", query, "the tag creation query")
	_, _, err = createTagQuery("EntityTag", "Simple Property", nil)
	assert.Error(t, err, "a property type that is not an identifier must be refused")

	query, _, err = createEntityQuery(oam.FQDN, nil)
	assert.NoError(t, err, "an entity creation query should build")
	assert.Equal(t, "CREATE (a:Entity:FQDN $props) RETURN a", query, "the entity creation query")
}
