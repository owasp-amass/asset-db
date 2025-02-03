// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"errors"
	"strings"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

func relationshipToEdge(rel neo4jdb.Relationship) (*types.Edge, error) {
	t, err := neo4jdb.GetProperty[neo4jdb.LocalDateTime](rel, "created_at")
	if err != nil {
		return nil, err
	}
	created := neo4jTimeToTime(t)

	t, err = neo4jdb.GetProperty[neo4jdb.LocalDateTime](rel, "updated_at")
	if err != nil {
		return nil, err
	}
	updated := neo4jTimeToTime(t)

	etype, err := neo4jdb.GetProperty[string](rel, "etype")
	if err != nil {
		return nil, err
	}
	rtype := oam.RelationType(etype)

	var r oam.Relation
	switch rtype {
	case oam.BasicDNSRelation:
		r, err = relationshipToBasicDNSRelation(rel)
	case oam.PortRelation:
		r, err = relationshipToPortRelation(rel)
	case oam.PrefDNSRelation:
		r, err = relationshipToPrefDNSRelation(rel)
	case oam.SimpleRelation:
		r, err = relationshipToSimpleRelation(rel)
	case oam.SRVDNSRelation:
		r, err = relationshipToSRVDNSRelation(rel)
	}
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("relation type not supported")
	}

	return &types.Edge{
		ID:        rel.GetElementId(),
		CreatedAt: created,
		LastSeen:  updated,
		Relation:  r,
	}, nil
}

func relationshipToBasicDNSRelation(rel neo4jdb.Relationship) (*dns.BasicDNSRelation, error) {
	num, err := neo4jdb.GetProperty[int64](rel, "header_rrtype")
	if err != nil {
		return nil, err
	}
	rrtype := int(num)

	num, err = neo4jdb.GetProperty[int64](rel, "header_class")
	if err != nil {
		return nil, err
	}
	class := int(num)

	num, err = neo4jdb.GetProperty[int64](rel, "header_ttl")
	if err != nil {
		return nil, err
	}
	ttl := int(num)

	return &dns.BasicDNSRelation{
		Name: strings.ToLower(rel.Type),
		Header: dns.RRHeader{
			RRType: rrtype,
			Class:  class,
			TTL:    ttl,
		},
	}, nil
}

func relationshipToPortRelation(rel neo4jdb.Relationship) (*general.PortRelation, error) {
	num, err := neo4jdb.GetProperty[int64](rel, "port_number")
	if err != nil {
		return nil, err
	}
	port := int(num)

	protocol, err := neo4jdb.GetProperty[string](rel, "protocol")
	if err != nil {
		return nil, err
	}

	return &general.PortRelation{
		Name:       strings.ToLower(rel.Type),
		PortNumber: port,
		Protocol:   protocol,
	}, nil
}

func relationshipToPrefDNSRelation(rel neo4jdb.Relationship) (*dns.PrefDNSRelation, error) {
	num, err := neo4jdb.GetProperty[int64](rel, "header_rrtype")
	if err != nil {
		return nil, err
	}
	rrtype := int(num)

	num, err = neo4jdb.GetProperty[int64](rel, "header_class")
	if err != nil {
		return nil, err
	}
	class := int(num)

	num, err = neo4jdb.GetProperty[int64](rel, "header_ttl")
	if err != nil {
		return nil, err
	}
	ttl := int(num)

	num, err = neo4jdb.GetProperty[int64](rel, "preference")
	if err != nil {
		return nil, err
	}
	pref := int(num)

	return &dns.PrefDNSRelation{
		Name: strings.ToLower(rel.Type),
		Header: dns.RRHeader{
			RRType: rrtype,
			Class:  class,
			TTL:    ttl,
		},
		Preference: pref,
	}, nil
}

func relationshipToSimpleRelation(rel neo4jdb.Relationship) (*general.SimpleRelation, error) {
	return &general.SimpleRelation{
		Name: strings.ToLower(rel.Type),
	}, nil
}

func relationshipToSRVDNSRelation(rel neo4jdb.Relationship) (*dns.SRVDNSRelation, error) {
	num, err := neo4jdb.GetProperty[int64](rel, "header_rrtype")
	if err != nil {
		return nil, err
	}
	rrtype := int(num)

	num, err = neo4jdb.GetProperty[int64](rel, "header_class")
	if err != nil {
		return nil, err
	}
	class := int(num)

	num, err = neo4jdb.GetProperty[int64](rel, "header_ttl")
	if err != nil {
		return nil, err
	}
	ttl := int(num)

	num, err = neo4jdb.GetProperty[int64](rel, "priority")
	if err != nil {
		return nil, err
	}
	priority := int(num)

	num, err = neo4jdb.GetProperty[int64](rel, "weight")
	if err != nil {
		return nil, err
	}
	weight := int(num)

	num, err = neo4jdb.GetProperty[int64](rel, "port")
	if err != nil {
		return nil, err
	}
	port := int(num)

	return &dns.SRVDNSRelation{
		Name: strings.ToLower(rel.Type),
		Header: dns.RRHeader{
			RRType: rrtype,
			Class:  class,
			TTL:    ttl,
		},
		Priority: priority,
		Weight:   weight,
		Port:     port,
	}, nil
}
