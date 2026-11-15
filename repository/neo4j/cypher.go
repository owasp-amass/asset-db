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

// tagIdentity is what makes a tag the same tag on its owner: a DNS record's
// name and data, a simple property's name and value, a source's name (its
// confidence is updated, not a second tag, as in the SQL repositories), and
// a vulnerability's ID and description.
func tagIdentity(prop oam.Property) (map[string]any, error) {
	switch v := prop.(type) {
	case *dns.DNSRecordProperty:
		return map[string]any{"property_name": v.PropertyName, "data": v.Data}, nil
	case *general.SimpleProperty:
		return map[string]any{"property_name": v.PropertyName, "property_value": v.PropertyValue}, nil
	case *general.SourceProperty:
		return map[string]any{"name": v.Source}, nil
	case *platform.VulnProperty:
		return map[string]any{"vuln_id": v.ID, "desc": v.Description}, nil
	case nil:
		return nil, errors.New("the property is nil")
	}

	return nil, errors.New("property type not supported")
}

// mergeTagQuery creates an EntityTag or EdgeTag node for its owner (owner is
// entity_id or edge_id) the first time the property is seen, and after that
// updates it, keeping its tag_id and created_at.
func mergeTagQuery(kind, owner, ownerID string, prop oam.Property, props map[string]any) (string, map[string]any,
	error) {
	if prop == nil {
		return "", nil, errors.New("the property is nil")
	}

	match, err := tagIdentity(prop)
	if err != nil {
		return "", nil, err
	}
	label, err := identifier(string(prop.PropertyType()))
	if err != nil {
		return "", nil, err
	}
	if _, err := identifier(owner); err != nil {
		return "", nil, err
	}

	seen := make(map[string]any, len(props))
	for k, v := range props {
		if k != "tag_id" && k != "created_at" {
			seen[k] = v
		}
	}

	params := map[string]any{"owner": ownerID, "props": props, "seen": seen}
	pairs := []string{owner + ": $owner"}
	for i, k := range slices.Sorted(mapKeys(match)) {
		p := "i" + strconv.Itoa(i)
		params[p] = match[k]
		pairs = append(pairs, k+": $"+p)
	}

	query := "MERGE (p:" + kind + ":" + label + " {" + strings.Join(pairs, ", ") + "}) ON CREATE SET p = $props " +
		"ON MATCH SET p += $seen RETURN p"
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
