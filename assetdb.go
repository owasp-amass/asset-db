// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assetdb

import (
	"time"

	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// AssetDB represents the asset database service.
type AssetDB struct {
	repository repository.Repository
}

// New creates a new assetDB instance.
// It initializes the asset database with the specified database type and DSN.
func New(dbType repository.DBType, dsn string) *AssetDB {
	database := repository.New(dbType, dsn)
	return &AssetDB{
		repository: database,
	}
}

// Close will close the assetdb and return any errors.
func (as *AssetDB) Close() error {
	return as.repository.Close()
}

// GetDBType returns the type of the underlying database.
func (as *AssetDB) GetDBType() string {
	return as.repository.GetDBType()
}

// Create creates a new entity in the database.
// If source is nil, the discovered entity will be created and relation will be ignored
// If source and relation are provided, the entity is created and linked to the source entity using the specified relation.
// It returns the newly created entity and an error, if any.
func (as *AssetDB) Create(source *types.Entity, relation string, discovered oam.Asset) (*types.Entity, error) {
	e, err := as.repository.CreateEntity(discovered)
	if err != nil || source == nil || relation == "" {
		return e, err
	}

	_, err = as.repository.Link(source, relation, e)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// UpdateEntityLastSeen updates the entity last seen field to the current time by its ID.
func (as *AssetDB) UpdateEntityLastSeen(id string) error {
	return as.repository.UpdateEntityLastSeen(id)
}

// DeleteEntity removes an entity in the database by its ID.
func (as *AssetDB) DeleteEntity(id string) error {
	return as.repository.DeleteEntity(id)
}

// DeleteRelation removes a relation in the database by its ID.
func (as *AssetDB) DeleteRelation(id string) error {
	return as.repository.DeleteRelation(id)
}

// FindByContent finds entities in the database based on their content and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// It returns a list of matching entities and an error, if any.
func (as *AssetDB) FindByContent(asset oam.Asset, since time.Time) ([]*types.Entity, error) {
	return as.repository.FindEntityByContent(asset, since)
}

// FindById finds an entity in the database by its ID and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// It returns the matching entity and an error, if any.
func (as *AssetDB) FindById(id string, since time.Time) (*types.Entity, error) {
	return as.repository.FindEntityById(id, since)
}

// FindByScope finds entities in the database by applying all the scope constraints provided
// and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// It returns the matching entities and an error, if any.
func (as *AssetDB) FindByScope(constraints []oam.Asset, since time.Time) ([]*types.Entity, error) {
	return as.repository.FindEntitiesByScope(constraints, since)
}

// FindByType finds all entities in the database of the provided asset type and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// It returns the matching entities and an error, if any.
func (as *AssetDB) FindByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	return as.repository.FindEntitiesByType(atype, since)
}

// Link creates a relation between two entities in the database.
// It takes the source entity, relation type, and destination entity as inputs.
// The relation is established by creating a new Relation in the database, linking the two entities.
// Returns the created relation as a types.Relation or an error if the link creation fails.
func (as *AssetDB) Link(source *types.Entity, relation string, destination *types.Entity) (*types.Relation, error) {
	return as.repository.Link(source, relation, destination)
}

// IncomingRelations finds all relations pointing to the entity for the specified relationTypes, if any.
// If since.IsZero(), the parameter will be ignored.
// If no relationTypes are specified, all incoming relations are returned.
func (as *AssetDB) IncomingRelations(entity *types.Entity, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	return as.repository.IncomingRelations(entity, since, relationTypes...)
}

// OutgoingRelations finds all relations from entity to another entity for the specified relationTypes, if any.
// If since.IsZero(), the parameter will be ignored.
// If no relationTypes are specified, all outgoing relations are returned.
func (as *AssetDB) OutgoingRelations(entity *types.Entity, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	return as.repository.OutgoingRelations(entity, since, relationTypes...)
}
