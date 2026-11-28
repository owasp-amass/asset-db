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

// CreateEntity implements the Repository interface.
func (neo *NeoRepository) CreateEntity(ctx context.Context, input *types.Entity) (*types.Entity, error) {
	if input == nil {
		return nil, errors.New("the input entity is nil")
	}

	filter, err := defaultContentFilter(input.Asset)
	if err != nil {
		return nil, err
	}

	var entity *types.Entity
	if input.ID != "" {
		// If the entity ID is set, it means that the entity was previously created
		// in the database, and we need to update that entity in the database
		entity = &types.Entity{
			ID:        input.ID,
			CreatedAt: input.CreatedAt,
			LastSeen:  time.Now(),
			Asset:     input.Asset,
		}
	} else if entities, err := neo.FindEntitiesByContent(ctx, input.Asset.AssetType(), time.Time{}, 1, filter); err == nil && len(entities) > 0 {
		// ensure that duplicate entities are not entered into the database
		entity = entities[0]
		entity.LastSeen = time.Now()
	}

	if entity != nil {
		if input.Asset.AssetType() != entity.Asset.AssetType() {
			return nil, errors.New("the asset type does not match the existing entity")
		}

		props, err := entityPropsMap(entity)
		if err != nil {
			return nil, err
		}

		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		result, err := neo4jdb.ExecuteQuery(tctx, neo.DB,
			"MATCH (a:Entity {entity_id: $eid}) SET a = $props RETURN a",
			map[string]interface{}{"eid": entity.ID, "props": props},
			neo4jdb.EagerResultTransformer,
			neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
		)
		if err != nil {
			return nil, err
		}
		if len(result.Records) == 0 {
			return nil, errors.New("no records returned from the query")
		}

		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "a")
		if err != nil {
			return nil, err
		}
		if isnil {
			return nil, errors.New("the record value for the node is nil")
		}

		entity = nil
		if e, err := nodeToEntity(node); err == nil && e != nil {
			entity = e
		}
	} else {
		if input.ID == "" {
			input.ID = neo.uniqueEntityID()
		}
		if input.CreatedAt.IsZero() {
			input.CreatedAt = time.Now()
		}
		if input.LastSeen.IsZero() {
			input.LastSeen = time.Now()
		}

		props, err := entityPropsMap(input)
		if err != nil {
			return nil, err
		}

		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		query, params, err := createEntityQuery(input.Asset.AssetType(), props)
		if err != nil {
			return nil, err
		}

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

		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "a")
		if err != nil {
			return nil, err
		}
		if isnil {
			return nil, errors.New("the record value for the node is nil")
		}

		if e, err := nodeToEntity(node); err == nil && e != nil {
			entity = e
		}
	}

	if entity == nil {
		return nil, errors.New("failed to create the entity")
	}
	return entity, nil
}

// CreateAsset implements the Repository interface.
func (neo *NeoRepository) CreateAsset(ctx context.Context, asset oam.Asset) (*types.Entity, error) {
	return neo.CreateEntity(ctx, &types.Entity{Asset: asset})
}

func (neo *NeoRepository) uniqueEntityID() string {
	tctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for {
		id := uuid.New().String()
		if _, err := neo.FindEntityById(tctx, id); err != nil {
			return id
		}
	}
}

// FindEntityById implements the Repository interface.
func (neo *NeoRepository) FindEntityById(ctx context.Context, id string) (*types.Entity, error) {
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(tctx, neo.DB,
		"MATCH (a:Entity {entity_id: $eid}) RETURN a",
		map[string]interface{}{"eid": id},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, fmt.Errorf("the entity with ID %s was not found", id)
	}

	node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "a")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the node is nil")
	}
	return nodeToEntity(node)
}

// FindEntitiesByContent implements the Repository interface.
func (neo *NeoRepository) FindEntitiesByContent(ctx context.Context, atype oam.AssetType, since time.Time, limit int, filters types.ContentFilters) ([]*types.Entity, error) {
	// a query whose RETURN follows ORDER BY is not valid Cypher, and a value
	// written into the query could change it: both are parameters now
	query, params, err := entitiesByContentQuery(atype, filters, since, limit)
	if err != nil {
		return nil, err
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
		return nil, errors.New("no entities found")
	}

	var results []*types.Entity
	for _, record := range result.Records {
		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](record, "a")
		if err != nil {
			return nil, err
		}
		if isnil {
			return nil, errors.New("the record value for the node is nil")
		}

		e, err := nodeToEntity(node)
		if err != nil {
			return nil, err
		}
		results = append(results, e)
	}

	if len(results) == 0 {
		return nil, errors.New("no entities successfully extracted")
	}
	return results, nil
}

func (neo *NeoRepository) FindEntitiesByType(ctx context.Context, atype oam.AssetType, since time.Time, limit int) ([]*types.Entity, error) {
	query, params, err := entitiesByTypeQuery(atype, since, limit)
	if err != nil {
		return nil, err
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
		return nil, errors.New("no entities of the specified type")
	}

	var results []*types.Entity
	for _, record := range result.Records {
		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](record, "a")
		if err != nil {
			return nil, err
		}
		if isnil {
			return nil, errors.New("the record value for the node is nil")
		}

		e, err := nodeToEntity(node)
		if err != nil {
			return nil, err
		}
		results = append(results, e)
	}

	if len(results) == 0 {
		return nil, errors.New("no entities of the specified type")
	}
	return results, nil
}

// DeleteEntity implements the Repository interface.
func (neo *NeoRepository) DeleteEntity(ctx context.Context, id string) error {
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, err := neo4jdb.ExecuteQuery(tctx, neo.DB,
		"MATCH (n:Entity {entity_id: $eid}) DETACH DELETE n"+countDeletion,
		map[string]interface{}{
			"eid": id,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)

	return err
}
