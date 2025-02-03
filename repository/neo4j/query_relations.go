// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"errors"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

func edgePropsMap(edge *types.Edge) (map[string]interface{}, error) {
	if edge == nil {
		return nil, errors.New("the edge is nil")
	}
	if edge.Relation == nil {
		return nil, errors.New("the relation is nil")
	}

	m := make(map[string]interface{})
	// begin populating the map of parameters
	m["etype"] = edge.Relation.RelationType()
	m["created_at"] = timeToNeo4jTime(edge.CreatedAt)
	m["updated_at"] = timeToNeo4jTime(edge.LastSeen)

	// Add the properties of the relation
	switch v := edge.Relation.(type) {
	case *dns.BasicDNSRelation:
		m["header_rrtype"] = v.Header.RRType
		m["header_class"] = v.Header.Class
		m["header_ttl"] = v.Header.TTL
	case *general.PortRelation:
		m["port_number"] = v.PortNumber
		m["protocol"] = v.Protocol
	case *dns.PrefDNSRelation:
		m["header_rrtype"] = v.Header.RRType
		m["header_class"] = v.Header.Class
		m["header_ttl"] = v.Header.TTL
		m["preference"] = v.Preference
	case *general.SimpleRelation:
	case *dns.SRVDNSRelation:
		m["header_rrtype"] = v.Header.RRType
		m["header_class"] = v.Header.Class
		m["header_ttl"] = v.Header.TTL
		m["priority"] = v.Priority
		m["weight"] = v.Weight
		m["port"] = v.Port
	default:
		return nil, errors.New("property type not supported")
	}

	return m, nil
}
