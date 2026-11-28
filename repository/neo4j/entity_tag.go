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

// CreateEntityTag implements the Repository interface. A tag is one node per
// entity and identity (see tagIdentity): a MERGE on them creates it the first
// time and updates it after, so a sighting is one query and concurrent
// writers do not add duplicates of it.
func (neo *NeoRepository) CreateEntityTag(ctx context.Context, entity *types.Entity, input *types.EntityTag) (*types.EntityTag, error) {
	if input == nil || input.Property == nil {
		return nil, errors.New("the input tag or its property is nil")
	}
	if entity == nil || entity.ID == "" {
		return nil, errors.New("the entity is missing")
	}

	now := time.Now()
	tag := &types.EntityTag{ID: input.ID, CreatedAt: input.CreatedAt, LastSeen: input.LastSeen,
		Property: input.Property, Entity: entity}
	if tag.ID == "" {
		tag.ID = uuid.New().String()
	}
	if tag.CreatedAt.IsZero() {
		tag.CreatedAt = now
	}
	if tag.LastSeen.IsZero() {
		tag.LastSeen = now
	}

	props, err := entityTagPropsMap(tag)
	if err != nil {
		return nil, err
	}

	query := "MATCH (p:EntityTag {tag_id: $tid}) SET p += $props RETURN p"
	params := map[string]any{"tid": input.ID, "props": props}
	if input.ID == "" {
		// a tag already stored for the entity keeps its id and first-seen time
		query, params, err = mergeTagQuery("EntityTag", "entity_id", entity.ID, input.Property, props)
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

	stored, err := nodeToEntityTag(node)
	if err != nil || stored == nil {
		return nil, fmt.Errorf("failed to read the stored tag: %v", err)
	}

	stored.Entity = entity
	return stored, nil
}

// CreateEntityProperty implements the Repository interface.
func (neo *NeoRepository) CreateEntityProperty(ctx context.Context, entity *types.Entity, prop oam.Property) (*types.EntityTag, error) {
	return neo.CreateEntityTag(ctx, entity, &types.EntityTag{Property: prop})
}

// FindEntityTagById implements the Repository interface.
func (neo *NeoRepository) FindEntityTagById(ctx context.Context, id string) (*types.EntityTag, error) {
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB,
		"MATCH (p:EntityTag {tag_id: $tid}) RETURN p",
		map[string]interface{}{"tid": id},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, fmt.Errorf("the entity tag with ID %s was not found", id)
	}

	node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "p")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the node is nil")
	}
	return nodeToEntityTag(node)
}

// FindEntityTags implements the Repository interface.
func (neo *NeoRepository) FindEntityTags(ctx context.Context, entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	query, params := tagsOfQuery("EntityTag", "entity_id", entity.ID, since)

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
		return nil, errors.New("no entity tags found")
	}

	var results []*types.EntityTag
	for _, record := range result.Records {
		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](record, "p")
		if err != nil {
			continue
		}
		if isnil {
			continue
		}

		tag, err := nodeToEntityTag(node)
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

// DeleteEntityTag implements the Repository interface.
func (neo *NeoRepository) DeleteEntityTag(ctx context.Context, id string) error {
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, err := neo4jdb.ExecuteQuery(tctx, neo.DB,
		"MATCH (n:EntityTag {tag_id: $tid}) DETACH DELETE n"+countDeletion,
		map[string]interface{}{
			"tid": id,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)

	return err
}
