// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

func nodeToEntityTag(node neo4jdb.Node) (*types.EntityTag, error) {
	id, err := neo4jdb.GetProperty[string](node, "tag_id")
	if err != nil {
		return nil, err
	}

	eid, err := neo4jdb.GetProperty[string](node, "entity_id")
	if err != nil {
		return nil, err
	}

	t, err := neo4jdb.GetProperty[neo4jdb.LocalDateTime](node, "created_at")
	if err != nil {
		return nil, err
	}
	created := neo4jTimeToTime(t)

	t, err = neo4jdb.GetProperty[neo4jdb.LocalDateTime](node, "updated_at")
	if err != nil {
		return nil, err
	}
	updated := neo4jTimeToTime(t)

	ttype, err := neo4jdb.GetProperty[string](node, "ttype")
	if err != nil {
		return nil, err
	}
	ptype := oam.PropertyType(ttype)

	prop, err := nodeToProperty(node, ptype)
	if err != nil {
		return nil, err
	}

	return &types.EntityTag{
		ID:        id,
		CreatedAt: created,
		LastSeen:  updated,
		Property:  prop,
		Entity:    &types.Entity{ID: eid},
	}, nil
}

func nodeToEdgeTag(node neo4jdb.Node) (*types.EdgeTag, error) {
	id, err := neo4jdb.GetProperty[string](node, "tag_id")
	if err != nil {
		return nil, err
	}

	eid, err := neo4jdb.GetProperty[string](node, "edge_id")
	if err != nil {
		return nil, err
	}

	t, err := neo4jdb.GetProperty[neo4jdb.LocalDateTime](node, "created_at")
	if err != nil {
		return nil, err
	}
	created := neo4jTimeToTime(t)

	t, err = neo4jdb.GetProperty[neo4jdb.LocalDateTime](node, "updated_at")
	if err != nil {
		return nil, err
	}
	updated := neo4jTimeToTime(t)

	ttype, err := neo4jdb.GetProperty[string](node, "ttype")
	if err != nil {
		return nil, err
	}
	ptype := oam.PropertyType(ttype)

	prop, err := nodeToProperty(node, ptype)
	if err != nil {
		return nil, err
	}

	return &types.EdgeTag{
		ID:        id,
		CreatedAt: created,
		LastSeen:  updated,
		Property:  prop,
		Edge:      &types.Edge{ID: eid},
	}, nil
}
