// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"errors"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/platform"
)

func nodeToProperty(node neo4jdb.Node, ptype oam.PropertyType) (oam.Property, error) {
	var err error
	var prop oam.Property

	switch ptype {
	case types.CachePropertyType:
		prop, err = nodeToCacheProperty(node)
	case oam.DNSRecordProperty:
		prop, err = nodeToDNSRecordProperty(node)
	case oam.SimpleProperty:
		prop, err = nodeToSimpleProperty(node)
	case oam.SourceProperty:
		prop, err = nodeToSourceProperty(node)
	case oam.VulnProperty:
		prop, err = nodeToVulnProperty(node)
	}
	if err != nil {
		return nil, err
	}
	if prop == nil {
		return nil, errors.New("property type not supported")
	}

	return prop, nil
}

func nodeToCacheProperty(node neo4jdb.Node) (*types.CacheProperty, error) {
	id, err := neo4jdb.GetProperty[string](node, "cache_id")
	if err != nil {
		return nil, err
	}

	refID, err := neo4jdb.GetProperty[string](node, "ref_id")
	if err != nil {
		return nil, err
	}

	timestamp, err := neo4jdb.GetProperty[string](node, "timestamp")
	if err != nil {
		return nil, err
	}

	return &types.CacheProperty{
		ID:        id,
		RefID:     refID,
		Timestamp: timestamp,
	}, nil
}

func nodeToDNSRecordProperty(node neo4jdb.Node) (*dns.DNSRecordProperty, error) {
	name, err := neo4jdb.GetProperty[string](node, "property_name")
	if err != nil {
		return nil, err
	}

	num, err := neo4jdb.GetProperty[int64](node, "header_rrtype")
	if err != nil {
		return nil, err
	}
	rrtype := int(num)

	num, err = neo4jdb.GetProperty[int64](node, "header_class")
	if err != nil {
		return nil, err
	}
	class := int(num)

	num, err = neo4jdb.GetProperty[int64](node, "header_ttl")
	if err != nil {
		return nil, err
	}
	ttl := int(num)

	data, err := neo4jdb.GetProperty[string](node, "data")
	if err != nil {
		return nil, err
	}

	return &dns.DNSRecordProperty{
		PropertyName: name,
		Header: dns.RRHeader{
			RRType: rrtype,
			Class:  class,
			TTL:    ttl,
		},
		Data: data,
	}, nil
}

func nodeToSimpleProperty(node neo4jdb.Node) (*general.SimpleProperty, error) {
	name, err := neo4jdb.GetProperty[string](node, "property_name")
	if err != nil {
		return nil, err
	}

	value, err := neo4jdb.GetProperty[string](node, "property_value")
	if err != nil {
		return nil, err
	}

	return &general.SimpleProperty{
		PropertyName:  name,
		PropertyValue: value,
	}, nil
}

func nodeToSourceProperty(node neo4jdb.Node) (*general.SourceProperty, error) {
	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	num, err := neo4jdb.GetProperty[int64](node, "confidence")
	if err != nil {
		return nil, err
	}
	conf := int(num)

	return &general.SourceProperty{
		Source:     name,
		Confidence: conf,
	}, nil
}

func nodeToVulnProperty(node neo4jdb.Node) (*platform.VulnProperty, error) {
	vid, err := neo4jdb.GetProperty[string](node, "vuln_id")
	if err != nil {
		return nil, err
	}

	desc, err := neo4jdb.GetProperty[string](node, "desc")
	if err != nil {
		return nil, err
	}

	source, err := neo4jdb.GetProperty[string](node, "source")
	if err != nil {
		return nil, err
	}

	category, err := neo4jdb.GetProperty[string](node, "category")
	if err != nil {
		return nil, err
	}

	enum, err := neo4jdb.GetProperty[string](node, "enum")
	if err != nil {
		return nil, err
	}

	ref, err := neo4jdb.GetProperty[string](node, "ref")
	if err != nil {
		return nil, err
	}

	return &platform.VulnProperty{
		ID:          vid,
		Description: desc,
		Source:      source,
		Category:    category,
		Enumeration: enum,
		Reference:   ref,
	}, nil
}
