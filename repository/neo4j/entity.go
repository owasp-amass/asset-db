// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"errors"
	"strconv"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
	"gorm.io/gorm"
)

// CreateEntity creates a new entity in the database.
// It takes an Entity as input and persists it in the database.
// The asset is serialized to JSON and stored in the Content field of the Entity struct.
// Returns the created entity as a types.Entity or an error if the creation fails.
func (neo *neoRepository) CreateEntity(input *types.Entity) (*types.Entity, error) {
	jsonContent, err := input.Asset.JSON()
	if err != nil {
		return nil, err
	}

	entity := Entity{
		Type:    string(input.Asset.AssetType()),
		Content: jsonContent,
	}

	// ensure that duplicate entities are not entered into the database
	if entities, err := neo.FindEntitiesByContent(input.Asset, time.Time{}); err == nil && len(entities) == 1 {
		e := entities[0]

		if input.Asset.AssetType() == e.Asset.AssetType() {
			if id, err := strconv.ParseUint(e.ID, 10, 64); err == nil {
				entity.ID = id
				entity.CreatedAt = e.CreatedAt
				entity.UpdatedAt = time.Now().UTC()
			}
		}
	} else {
		if input.CreatedAt.IsZero() {
			entity.CreatedAt = time.Now().UTC()
		} else {
			entity.CreatedAt = input.CreatedAt.UTC()
		}

		if input.LastSeen.IsZero() {
			entity.UpdatedAt = time.Now().UTC()
		} else {
			entity.UpdatedAt = input.LastSeen.UTC()
		}
	}

	result := sql.db.Save(&entity)
	if err := result.Error; err != nil {
		return nil, err
	}

	return &types.Entity{
		ID:        strconv.FormatUint(entity.ID, 10),
		CreatedAt: entity.CreatedAt.In(time.UTC).Local(),
		LastSeen:  entity.UpdatedAt.In(time.UTC).Local(),
		Asset:     input.Asset,
	}, nil
}

// CreateAsset creates a new entity in the database.
// It takes an oam.Asset as input and persists it in the database.
// The asset is serialized to JSON and stored in the Content field of the Entity struct.
// Returns the created entity as a types.Entity or an error if the creation fails.
func (neo *neoRepository) CreateAsset(asset oam.Asset) (*types.Entity, error) {
	return neo.CreateEntity(&types.Entity{Asset: asset})
}

// UpdateEntityLastSeen performs an update on the entity.
func (neo *neoRepository) UpdateEntityLastSeen(id string) error {
	result := sql.db.Exec("UPDATE entities SET updated_at = current_timestamp WHERE entity_id = ?", id)
	if err := result.Error; err != nil {
		return err
	}
	return nil
}

// FindEntityById finds an entity in the database by the ID.
// It takes a string representing the entity ID and retrieves the corresponding entity from the database.
// Returns the found entity as a types.Entity or an error if the asset is not found.
func (neo *neoRepository) FindEntityById(id string) (*types.Entity, error) {
	entityId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return nil, err
	}

	entity := Entity{ID: entityId}
	result := sql.db.First(&entity)
	if err := result.Error; err != nil {
		return nil, err
	}

	assetData, err := entity.Parse()
	if err != nil {
		return nil, err
	}

	return &types.Entity{
		ID:        strconv.FormatUint(entity.ID, 10),
		CreatedAt: entity.CreatedAt.In(time.UTC).Local(),
		LastSeen:  entity.UpdatedAt.In(time.UTC).Local(),
		Asset:     assetData,
	}, nil
}

// FindEntitiesByContent finds entities in the database that match the provided asset data and last seen after
// the since parameter. It takes an oam.Asset as input and searches for entities with matching content in the database.
// If since.IsZero(), the parameter will be ignored.
// The asset data is serialized to JSON and compared against the Content field of the Entity struct.
// Returns a slice of matching entities as []*types.Entity or an error if the search fails.
func (neo *neoRepository) FindEntitiesByContent(assetData oam.Asset, since time.Time) ([]*types.Entity, error) {
	jsonContent, err := assetData.JSON()
	if err != nil {
		return nil, err
	}

	entity := Entity{
		Type:    string(assetData.AssetType()),
		Content: jsonContent,
	}

	jsonQuery, err := entity.JSONQuery()
	if err != nil {
		return nil, err
	}

	tx := sql.db.Where("etype = ?", entity.Type)
	if !since.IsZero() {
		tx = tx.Where("updated_at >= ?", since.UTC())
	}

	var entities []Entity
	tx = tx.Where(jsonQuery).Find(&entities)
	if err := tx.Error; err != nil {
		return nil, err
	}

	var results []*types.Entity
	for _, e := range entities {
		if assetData, err := e.Parse(); err == nil {
			results = append(results, &types.Entity{
				ID:        strconv.FormatUint(e.ID, 10),
				CreatedAt: e.CreatedAt.In(time.UTC).Local(),
				LastSeen:  e.UpdatedAt.In(time.UTC).Local(),
				Asset:     assetData,
			})
		}
	}

	if len(results) == 0 {
		return nil, errors.New("zero entities found")
	}
	return results, nil
}

// FindEntitiesByType finds all entities in the database of the provided asset type and last seen after the since parameter.
// It takes an asset type and retrieves the corresponding entities from the database.
// If since.IsZero(), the parameter will be ignored.
// Returns a slice of matching entities as []*types.Entity or an error if the search fails.
func (neo *neoRepository) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	var entities []Entity
	var result *gorm.DB

	if since.IsZero() {
		result = sql.db.Where("etype = ?", atype).Find(&entities)
	} else {
		result = sql.db.Where("etype = ? AND updated_at >= ?", atype, since.UTC()).Find(&entities)
	}
	if err := result.Error; err != nil {
		return nil, err
	}

	var results []*types.Entity
	for _, e := range entities {
		if f, err := e.Parse(); err == nil {
			results = append(results, &types.Entity{
				ID:        strconv.FormatUint(e.ID, 10),
				CreatedAt: e.CreatedAt.In(time.UTC).Local(),
				LastSeen:  e.UpdatedAt.In(time.UTC).Local(),
				Asset:     f,
			})
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := neo4jdb.ExecuteQuery(ctx, neo.db,
		"MATCH (n:Entity {entity_id: $entity_id}) DETACH DELETE n",
		map[string]interface{}{
			"entity_id": id,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)

	return err
}
