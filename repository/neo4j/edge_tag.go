// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// CreateEdgeTag implements the Repository interface. A tag is one node per
// edge and identity (see tagIdentity): a MERGE on them creates it the first
// time and updates it after, so a sighting is one query and concurrent
// writers do not add duplicates of it.
func (neo *NeoRepository) CreateEdgeTag(ctx context.Context, edge *types.Edge, input *types.EdgeTag) (*types.EdgeTag, error) {
	if input == nil || input.Property == nil {
		return nil, errors.New("the input tag or its property is nil")
	}
	if edge == nil || edge.ID == "" {
		return nil, errors.New("the edge is missing")
	}

	now := time.Now()
	tag := &types.EdgeTag{ID: input.ID, CreatedAt: input.CreatedAt, LastSeen: input.LastSeen,
		Property: input.Property, Edge: edge}
	if tag.ID == "" {
		tag.ID = uuid.New().String()
	}
	if tag.CreatedAt.IsZero() {
		tag.CreatedAt = now
	}
	if tag.LastSeen.IsZero() {
		tag.LastSeen = now
	}

	props, err := edgeTagPropsMap(tag)
	if err != nil {
		return nil, err
	}

	query := "MATCH (p:EdgeTag {tag_id: $tid}) SET p += $props RETURN p"
	params := map[string]any{"tid": input.ID, "props": props}
	if input.ID == "" {
		// a tag already stored for the edge keeps its id and first-seen time
		query, params, err = mergeTagQuery("EdgeTag", "edge_id", edge.ID, input.Property, props)
		if err != nil {
			return nil, err
		}
	}

	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB, query, params,
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, errors.New("no records returned from the query")
	}

	node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "p")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the node is nil")
	}

	stored, err := nodeToEdgeTag(node)
	if err != nil || stored == nil {
		return nil, fmt.Errorf("failed to read the stored tag: %v", err)
	}

	stored.Edge = edge
	return stored, nil
}

// CreateEdgeProperty implements the Repository interface.
func (neo *NeoRepository) CreateEdgeProperty(ctx context.Context, edge *types.Edge, prop oam.Property) (*types.EdgeTag, error) {
	return neo.CreateEdgeTag(ctx, edge, &types.EdgeTag{Property: prop})
}

// FindEdgeTagById implements the Repository interface.
func (neo *NeoRepository) FindEdgeTagById(ctx context.Context, id string) (*types.EdgeTag, error) {
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB,
		"MATCH (p:EdgeTag {tag_id: $tid}) RETURN p",
		map[string]interface{}{"tid": id},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, fmt.Errorf("the edge tag with ID %s was not found", id)
	}

	node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "p")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the node is nil")
	}
	return nodeToEdgeTag(node)
}

// FindEdgeTags implements the Repository interface.
func (neo *NeoRepository) FindEdgeTags(ctx context.Context, edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {
	query, params := tagsOfQuery("EdgeTag", "edge_id", edge.ID, since)

	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB, query, params,
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, errors.New("no edge tags found")
	}

	var results []*types.EdgeTag
	for _, record := range result.Records {
		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](record, "p")
		if err != nil {
			continue
		}
		if isnil {
			continue
		}

		tag, err := nodeToEdgeTag(node)
		if err != nil {
			continue
		}

		if len(names) > 0 {
			var found bool
			n := tag.Property.Name()

			for _, name := range names {
				if name == n {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		results = append(results, tag)
	}

	if len(results) == 0 {
		return nil, errors.New("zero tags found")
	}
	return results, nil
}

// DeleteEdgeTag implements the Repository interface.
func (neo *NeoRepository) DeleteEdgeTag(ctx context.Context, id string) error {
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, err := neo4jdb.ExecuteQuery(tctx, neo.DB,
		"MATCH (n:EdgeTag {tag_id: $tid}) DETACH DELETE n"+countDeletion,
		map[string]interface{}{
			"tid": id,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)

	return err
}
