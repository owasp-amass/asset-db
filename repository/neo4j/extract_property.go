// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"errors"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/property"
)

func nodeToProperty(node neo4jdb.Node, ptype oam.PropertyType) (oam.Property, error) {
	var err error
	var prop oam.Property

	switch ptype {
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

func nodeToSimpleProperty(node neo4jdb.Node) (*property.SimpleProperty, error) {
	name, err := neo4jdb.GetProperty[string](node, "property_name")
	if err != nil {
		return nil, err
	}

	value, err := neo4jdb.GetProperty[string](node, "property_value")
	if err != nil {
		return nil, err
	}

	return &property.SimpleProperty{
		PropertyName:  name,
		PropertyValue: value,
	}, nil
}

func nodeToSourceProperty(node neo4jdb.Node) (*property.SourceProperty, error) {
	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	num, err := neo4jdb.GetProperty[int64](node, "confidence")
	if err != nil {
		return nil, err
	}
	conf := int(num)

	return &property.SourceProperty{
		Source:     name,
		Confidence: conf,
	}, nil
}

func nodeToVulnProperty(node neo4jdb.Node) (*property.VulnProperty, error) {
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

	return &property.VulnProperty{
		ID:          vid,
		Description: desc,
		Source:      source,
		Category:    category,
		Enumeration: enum,
		Reference:   ref,
	}, nil
}
