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
// If the edge is provided, the entity is created and linked to the source entity using the specified edge.
// It returns the newly created entity and an error, if any.
func (as *AssetDB) Create(edge *types.Edge, asset oam.Asset) (*types.Entity, error) {
	e, err := as.repository.CreateEntity(asset)
	if err != nil || edge == nil || edge.FromEntity == nil || edge.Relation == nil {
		return e, err
	}

	edge.ToEntity = e
	_, err = as.repository.Link(edge)
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

// DeleteEdge removes a relation in the database by its ID.
func (as *AssetDB) DeleteEdge(id string) error {
	return as.repository.DeleteEdge(id)
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

// Link creates an edge between two entities in the database.
// The link is established by creating a new Edge in the database, linking the two entities.
// Returns the created edge as a types.Edge or an error if the link creation fails.
func (as *AssetDB) Link(edge *types.Edge) (*types.Edge, error) {
	return as.repository.Link(edge)
}

// IncomingEdges finds all edges pointing to the entity for the specified labels, if any.
// If since.IsZero(), the parameter will be ignored.
// If no labels are specified, all incoming edges are returned.
func (as *AssetDB) IncomingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	return as.repository.IncomingEdges(entity, since, labels...)
}

// OutgoingEdges finds all edges from entity to another entity for the specified labels, if any.
// If since.IsZero(), the parameter will be ignored.
// If no labels are specified, all outgoing edges are returned.
func (as *AssetDB) OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	return as.repository.OutgoingEdges(entity, since, labels...)
}
