// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

// CreateEntity creates a new entity in the database.
// It takes an Entity as input and persists it in the database.
// Returns the created entity as a types.Entity or an error if the creation fails.
func (neo *neoRepository) CreateEntity(input *types.Entity) (*types.Entity, error) {
	if input == nil {
		return nil, errors.New("the input entity is nil")
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
	} else if entities, err := neo.FindEntitiesByContent(input.Asset, time.Time{}); err == nil && len(entities) > 0 {
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

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := neo4jdb.ExecuteQuery(ctx, neo.db,
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

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		query := fmt.Sprintf("CREATE (a:Entity:%s $props) RETURN a", input.Asset.AssetType())
		result, err := neo4jdb.ExecuteQuery(ctx, neo.db, query,
			map[string]interface{}{"props": props},
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

// CreateAsset creates a new entity in the database.
// It takes an oam.Asset as input and persists it in the database.
// The asset is serialized to JSON and stored in the Content field of the Entity struct.
// Returns the created entity as a types.Entity or an error if the creation fails.
func (neo *neoRepository) CreateAsset(asset oam.Asset) (*types.Entity, error) {
	return neo.CreateEntity(&types.Entity{Asset: asset})
}

func (neo *neoRepository) uniqueEntityID() string {
	for {
		id := uuid.New().String()
		if _, err := neo.FindEntityById(id); err != nil {
			return id
		}
	}
}

// FindEntityById finds an entity in the database by the ID.
// It takes a string representing the entity ID and retrieves the corresponding entity from the database.
// Returns the found entity as a types.Entity or an error if the asset is not found.
func (neo *neoRepository) FindEntityById(id string) (*types.Entity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db,
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

// FindEntitiesByContent finds entities in the database that match the provided asset data and last seen after
// the since parameter. It takes an oam.Asset as input and searches for entities with matching content in the database.
// If since.IsZero(), the parameter will be ignored.
// The asset data is serialized to JSON and compared against the Content field of the Entity struct.
// Returns a slice of matching entities as []*types.Entity or an error if the search fails.
func (neo *neoRepository) FindEntitiesByContent(assetData oam.Asset, since time.Time) ([]*types.Entity, error) {
	qnode, err := queryNodeByAssetKey("a", assetData)
	if err != nil {
		return nil, err
	}

	query := "MATCH " + qnode + " RETURN a"
	if !since.IsZero() {
		query = fmt.Sprintf("MATCH %s WHERE a.updated_at >= localDateTime('%s') RETURN a", qnode, timeToNeo4jTime(since))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db, query, nil,
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, errors.New("no entities found")
	}

	node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "a")
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
	return []*types.Entity{e}, nil
}

// FindEntitiesByType finds all entities in the database of the provided asset type and last seen after the since parameter.
// It takes an asset type and retrieves the corresponding entities from the database.
// If since.IsZero(), the parameter will be ignored.
// Returns a slice of matching entities as []*types.Entity or an error if the search fails.
func (neo *neoRepository) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	query := fmt.Sprintf("MATCH (a:%s) RETURN a", string(atype))
	if !since.IsZero() {
		query = fmt.Sprintf("MATCH (a:%s) WHERE a.updated_at >= localDateTime('%s') RETURN a", string(atype), timeToNeo4jTime(since))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db, query, nil,
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

// DeleteEntity removes an entity in the database by its ID.
// It takes a string representing the entity ID and removes the corresponding entity from the database.
// Returns an error if the entity is not found.
func (neo *neoRepository) DeleteEntity(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := neo4jdb.ExecuteQuery(ctx, neo.db,
		"MATCH (n:Entity {entity_id: $eid}) DETACH DELETE n",
		map[string]interface{}{
			"eid": id,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)

	return err
}
