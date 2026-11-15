// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/platform"
)

// The queries below take every value as a parameter, so a value can never
// change a query, and Neo4j can reuse a query's plan. Labels, relationship
// types and property keys cannot be parameters, so they are checked to be
// plain identifiers before they are written into a query.

var identRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// identifier returns s for use as a label, relationship type or property
// key, or an error when it is not letters, digits and underscores.
func identifier(s string) (string, error) {
	if !identRE.MatchString(s) {
		return "", fmt.Errorf("%q cannot name a label, relationship type or property", s)
	}

	return s, nil
}

// sinceClause adds an updated_at bound on variable v when since is set.
func sinceClause(v string, since time.Time, params map[string]any) string {
	if since.IsZero() {
		return ""
	}

	params["since"] = timeToNeo4jTime(since)
	return v + ".updated_at >= $since"
}

// where joins conditions into a WHERE clause, or nothing.
func where(conds ...string) string {
	conds = slices.DeleteFunc(conds, func(c string) bool { return c == "" })
	if len(conds) == 0 {
		return ""
	}

	return " WHERE " + strings.Join(conds, " AND ")
}

// createEntityQuery creates an entity node labeled with its asset type.
func createEntityQuery(atype oam.AssetType, props map[string]any) (string, map[string]any, error) {
	label, err := assetLabel(atype)
	if err != nil {
		return "", nil, err
	}

	return "CREATE (a:Entity:" + label + " $props) RETURN a", map[string]any{"props": props}, nil
}

// entitiesByContentQuery finds the entities of a type whose properties
// equal every filter, the most recently updated first.
func entitiesByContentQuery(atype oam.AssetType, filters map[string]any, since time.Time,
	limit int) (string, map[string]any, error) {
	label, err := assetLabel(atype)
	if err != nil {
		return "", nil, err
	}
	if len(filters) == 0 {
		return "", nil, errors.New("no content filters were provided")
	}

	params := map[string]any{}
	var conds []string
	for i, key := range slices.Sorted(mapKeys(filters)) {
		k, err := identifier(key)
		if err != nil {
			return "", nil, err
		}

		p := "f" + strconv.Itoa(i)
		params[p] = filters[key]
		conds = append(conds, "a."+k+" = $"+p)
	}
	conds = append(conds, sinceClause("a", since, params))

	query := "MATCH (a:Entity:" + label + ")" + where(conds...) + " RETURN a ORDER BY a.updated_at DESC"
	return query + limitClause(limit, params), params, nil
}

// entitiesByTypeQuery finds the entities of a type, the most recently
// updated first.
func entitiesByTypeQuery(atype oam.AssetType, since time.Time, limit int) (string, map[string]any, error) {
	label, err := assetLabel(atype)
	if err != nil {
		return "", nil, err
	}

	params := map[string]any{}
	query := "MATCH (a:Entity:" + label + ")" + where(sinceClause("a", since, params)) +
		" RETURN a ORDER BY a.updated_at DESC"
	return query + limitClause(limit, params), params, nil
}

func limitClause(limit int, params map[string]any) string {
	if limit <= 0 {
		return ""
	}

	params["limit"] = limit
	return " LIMIT $limit"
}

// createEdgeQuery creates a relationship of the relation's type between
// two entities.
func createEdgeQuery(fromID, toID, label string, props map[string]any) (string, map[string]any, error) {
	rtype, err := identifier(strings.ToUpper(label))
	if err != nil {
		return "", nil, err
	}

	return "MATCH (from:Entity {entity_id: $fid}) MATCH (to:Entity {entity_id: $tid}) CREATE (from)-[r:" + rtype +
		" $props]->(to) RETURN r", map[string]any{"fid": fromID, "tid": toID, "props": props}, nil
}

// edgeSeenQuery sets when an edge was last seen.
func edgeSeenQuery(id string, updated time.Time) (string, map[string]any) {
	return "MATCH ()-[r]->() WHERE elementId(r) = $eid SET r.updated_at = $updated",
		map[string]any{"eid": id, "updated": timeToNeo4jTime(updated)}
}

// edgesQuery finds an entity's incoming or outgoing edges with the entity
// at their other end.
func edgesQuery(entityID string, incoming bool, since time.Time) (string, map[string]any) {
	params := map[string]any{"eid": entityID}
	if incoming {
		return "MATCH (:Entity {entity_id: $eid})<-[r]-(from:Entity)" + where(sinceClause("r", since, params)) +
			" RETURN r, from.entity_id AS fid", params
	}

	return "MATCH (:Entity {entity_id: $eid})-[r]->(to:Entity)" + where(sinceClause("r", since, params)) +
		" RETURN r, to.entity_id AS tid", params
}

// createTagQuery creates an EntityTag or EdgeTag node labeled with its
// property type.
func createTagQuery(kind, ptype string, props map[string]any) (string, map[string]any, error) {
	label, err := identifier(ptype)
	if err != nil {
		return "", nil, err
	}

	return "CREATE (p:" + kind + ":" + label + " $props) RETURN p", map[string]any{"props": props}, nil
}

// tagsOfQuery finds the tags of an entity (owner entity_id) or an edge
// (owner edge_id).
func tagsOfQuery(kind, owner, id string, since time.Time) (string, map[string]any) {
	params := map[string]any{"id": id}
	return "MATCH (p:" + kind + " {" + owner + ": $id})" + where(sinceClause("p", since, params)) + " RETURN p",
		params
}

// tagsByContentQuery finds the tags of a kind holding a property's
// identifying values.
func tagsByContentQuery(kind string, prop oam.Property, since time.Time) (string, map[string]any, error) {
	if prop == nil {
		return "", nil, errors.New("the property is nil")
	}

	var match map[string]any
	switch v := prop.(type) {
	case *dns.DNSRecordProperty:
		match = map[string]any{"property_name": v.PropertyName, "data": v.Data}
	case *general.SimpleProperty:
		match = map[string]any{"property_name": v.PropertyName, "property_value": v.PropertyValue}
	case *general.SourceProperty:
		match = map[string]any{"name": v.Source, "confidence": v.Confidence}
	case *platform.VulnProperty:
		match = map[string]any{"vuln_id": v.ID, "desc": v.Description}
	default:
		return "", nil, errors.New("property type not supported")
	}

	params := map[string]any{}
	var pairs []string
	for _, k := range slices.Sorted(mapKeys(match)) {
		params[k] = match[k]
		pairs = append(pairs, k+": $"+k)
	}

	query := "MATCH (p:" + kind + " {" + strings.Join(pairs, ", ") + "})" + where(sinceClause("p", since, params)) +
		" RETURN p"
	return query, params, nil
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
