// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"errors"
	"fmt"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/platform"
)

func entityTagPropsMap(tag *types.EntityTag) (map[string]interface{}, error) {
	if tag == nil {
		return nil, errors.New("the entity tag is nil")
	}
	if tag.Property == nil {
		return nil, errors.New("the property is nil")
	}

	m := make(map[string]interface{})
	// begin populating the map of parameters
	m["ttype"] = tag.Property.PropertyType()
	m["tag_id"] = tag.ID
	m["created_at"] = timeToNeo4jTime(tag.CreatedAt)
	m["updated_at"] = timeToNeo4jTime(tag.LastSeen)
	m["entity_id"] = tag.Entity.ID

	// Add the properties of the property
	props, err := propertyPropsMap(tag.Property)
	if err != nil {
		return nil, err
	}

	for k, v := range props {
		m[k] = v
	}

	return m, nil
}

func edgeTagPropsMap(tag *types.EdgeTag) (map[string]interface{}, error) {
	if tag == nil {
		return nil, errors.New("the edge tag is nil")
	}
	if tag.Property == nil {
		return nil, errors.New("the property is nil")
	}

	m := make(map[string]interface{})
	// begin populating the map of parameters
	m["ttype"] = tag.Property.PropertyType()
	m["tag_id"] = tag.ID
	m["created_at"] = timeToNeo4jTime(tag.CreatedAt)
	m["updated_at"] = timeToNeo4jTime(tag.LastSeen)
	m["edge_id"] = tag.Edge.ID

	// Add the properties of the property
	props, err := propertyPropsMap(tag.Property)
	if err != nil {
		return nil, err
	}

	for k, v := range props {
		m[k] = v
	}

	return m, nil
}

func propertyPropsMap(prop oam.Property) (map[string]interface{}, error) {
	m := make(map[string]interface{})

	// begin populating the map of parameters
	switch v := prop.(type) {
	case *dns.DNSRecordProperty:
		m["property_name"] = v.PropertyName
		m["header_rrtype"] = v.Header.RRType
		m["header_class"] = v.Header.Class
		m["header_ttl"] = v.Header.TTL
		m["data"] = v.Data
	case *general.SimpleProperty:
		m["property_name"] = v.PropertyName
		m["property_value"] = v.PropertyValue
	case *general.SourceProperty:
		m["name"] = v.Source
		m["confidence"] = v.Confidence
	case *platform.VulnProperty:
		m["vuln_id"] = v.ID
		m["desc"] = v.Description
		m["category"] = v.Category
		m["enum"] = v.Enumeration
		m["ref"] = v.Reference
	default:
		return nil, errors.New("property type not supported")
	}

	return m, nil
}

func queryNodeByPropertyKeyValue(varname, label string, prop oam.Property) (string, error) {
	if prop == nil {
		return "", errors.New("the property is nil")
	}

	var node string
	switch v := prop.(type) {
	case *dns.DNSRecordProperty:
		node = fmt.Sprintf("(%s:%s {%s: '%s', %s: %d})", varname, label, "property_name", v.PropertyName, "data", v.Data)
	case *general.SimpleProperty:
		node = fmt.Sprintf("(%s:%s {%s: '%s', %s: '%s'})", varname, label, "property_name", v.PropertyName, "property_value", v.PropertyValue)
	case *general.SourceProperty:
		node = fmt.Sprintf("(%s:%s {%s: '%s', %s: %d})", varname, label, "name", v.Source, "confidence", v.Confidence)
	case *platform.VulnProperty:
		node = fmt.Sprintf("(%s:%s {%s: '%s', %s: '%s'})", varname, label, "vuln_id", v.ID, "desc", v.Description)
	}
	if node == "" {
		return "", errors.New("asset type not supported")
	}

	return node, nil
}
