// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlrepo

import (
	"errors"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"gorm.io/gorm"
)

// CreateEntity creates a new entity in the database.
// It takes an oam.Asset as input and persists it in the database.
// The entity is serialized to JSON and stored in the Content field of the Entity struct.
// Returns the created entity as a types.Entity or an error if the creation fails.
func (sql *sqlRepository) CreateEntity(assetData oam.Asset) (*types.Entity, error) {
	jsonContent, err := assetData.JSON()
	if err != nil {
		return nil, err
	}

	entity := Entity{
		Type:    string(assetData.AssetType()),
		Content: jsonContent,
	}

	// ensure that duplicate entities are not entered into the database
	if entities, err := sql.FindEntityByContent(assetData, time.Time{}); err == nil && len(entities) > 0 {
		for _, e := range entities {
			if assetData.AssetType() == e.Asset.AssetType() {
				if id, err := strconv.ParseUint(e.ID, 10, 64); err == nil {
					entity.ID = id
					entity.CreatedAt = e.CreatedAt

					if sql.UpdateEntityLastSeen(e.ID) == nil {
						if f, err := sql.FindEntityById(e.ID); err == nil && f != nil {
							entity.LastSeen = f.LastSeen
							break
						}
					}
				}
			}
		}
	}

	result := sql.db.Save(&entity)
	if result.Error != nil {
		return nil, result.Error
	}

	return &types.Entity{
		ID:        strconv.FormatUint(entity.ID, 10),
		CreatedAt: entity.CreatedAt,
		LastSeen:  entity.LastSeen,
		Asset:     assetData,
	}, nil
}

// UpdateEntityLastSeen performs an update on the entity.
func (sql *sqlRepository) UpdateEntityLastSeen(id string) error {
	result := sql.db.Exec("UPDATE entities SET last_seen = current_timestamp WHERE entity_id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// DeleteEntity removes an entity in the database by its ID.
// It takes a string representing the entity ID and removes the corresponding entity from the database.
// Returns an error if the entity is not found.
func (sql *sqlRepository) DeleteEntity(id string) error {
	entityId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}

	entity := Entity{ID: entityId}
	result := sql.db.Delete(&entity)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// FindEntityByContent finds entity in the database that match the provided asset data and last seen after the since parameter.
// It takes an oam.Asset as input and searches for entities with matching content in the database.
// If since.IsZero(), the parameter will be ignored.
// The asset data is serialized to JSON and compared against the Content field of the Entity struct.
// Returns a slice of matching entities as []*types.Entity or an error if the search fails.
func (sql *sqlRepository) FindEntityByContent(assetData oam.Asset, since time.Time) ([]*types.Entity, error) {
	jsonContent, err := assetData.JSON()
	if err != nil {
		return []*types.Entity{}, err
	}

	entity := Entity{
		Type:    string(assetData.AssetType()),
		Content: jsonContent,
	}
	if !since.IsZero() {
		entity.LastSeen = since
	}

	jsonQuery, err := entity.JSONQuery()
	if err != nil {
		return []*types.Entity{}, err
	}

	var entities []Entity
	var result *gorm.DB
	if since.IsZero() {
		result = sql.db.Where("etype = ?", entity.Type).Find(&entities, jsonQuery)
	} else {
		result = sql.db.Where("etype = ? AND last_seen >= ?", entity.Type, since.UTC()).Find(&entities, jsonQuery)
	}
	if result.Error != nil {
		return []*types.Entity{}, result.Error
	}

	var storedEntities []*types.Entity
	for _, e := range entities {
		assetData, err := e.Parse()
		if err != nil {
			return []*types.Entity{}, err
		}

		storedEntities = append(storedEntities, &types.Entity{
			ID:        strconv.FormatUint(e.ID, 10),
			CreatedAt: e.CreatedAt,
			LastSeen:  e.LastSeen,
			Asset:     assetData,
		})
	}

	return storedEntities, nil
}

// FindEntityById finds an entity in the database by the ID.
// It takes a string representing the entity ID and retrieves the corresponding entity from the database.
// Returns the found entity as a types.Entity or an error if the asset is not found.
func (sql *sqlRepository) FindEntityById(id string) (*types.Entity, error) {
	entityId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return nil, err
	}

	entity := Entity{ID: entityId}
	result := sql.db.First(&entity)
	if result.Error != nil {
		return nil, result.Error
	}

	assetData, err := entity.Parse()
	if err != nil {
		return nil, err
	}

	return &types.Entity{
		ID:        strconv.FormatUint(entity.ID, 10),
		CreatedAt: entity.CreatedAt,
		LastSeen:  entity.LastSeen,
		Asset:     assetData,
	}, nil
}

// FindEntitiesByType finds all entities in the database of the provided asset type and last seen after the since parameter.
// It takes an asset type and retrieves the corresponding entities from the database.
// If since.IsZero(), the parameter will be ignored.
// Returns a slice of matching entities as []*types.Entity or an error if the search fails.
func (sql *sqlRepository) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	var entities []Entity
	var result *gorm.DB

	if since.IsZero() {
		result = sql.db.Where("etype = ?", atype).Find(&entities)
	} else {
		result = sql.db.Where("etype = ? AND last_seen >= ?", atype, since.UTC()).Find(&entities)
	}
	if result.Error != nil {
		return []*types.Entity{}, result.Error
	}

	var results []*types.Entity
	for _, e := range entities {
		if f, err := e.Parse(); err == nil {
			results = append(results, &types.Entity{
				ID:        strconv.FormatUint(e.ID, 10),
				CreatedAt: e.CreatedAt,
				LastSeen:  e.LastSeen,
				Asset:     f,
			})
		}
	}

	if len(results) == 0 {
		return []*types.Entity{}, errors.New("no entities of the specified type")
	}
	return results, nil
}