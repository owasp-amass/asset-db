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
	Repo repository.Repository
}

// Create creates a new entity in the database.
// If the edge is provided, the entity is created and linked to the source entity using the specified edge.
// It returns the newly created entity and an error, if any.
func (as *AssetDB) Create(edge *types.Edge, asset oam.Asset) (*types.Entity, error) {
	e, err := as.Repo.CreateEntity(asset)
	if err != nil || edge == nil || edge.FromEntity == nil || edge.Relation == nil {
		return e, err
	}

	edge.ToEntity = e
	_, err = as.Repo.Link(edge)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// UpdateEntityLastSeen updates the entity last seen field to the current time by its ID.
func (as *AssetDB) UpdateEntityLastSeen(id string) error {
	return as.Repo.UpdateEntityLastSeen(id)
}

// DeleteEntity removes an entity in the database by its ID.
func (as *AssetDB) DeleteEntity(id string) error {
	return as.Repo.DeleteEntity(id)
}

// DeleteEdge removes a relation in the database by its ID.
func (as *AssetDB) DeleteEdge(id string) error {
	return as.Repo.DeleteEdge(id)
}

// FindByContent finds entities in the database based on their content and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// It returns a list of matching entities and an error, if any.
func (as *AssetDB) FindByContent(asset oam.Asset, since time.Time) ([]*types.Entity, error) {
	return as.Repo.FindEntityByContent(asset, since)
}

// FindEntityById finds an entity in the database by the ID.
// It returns the matching entity and an error, if any.
func (as *AssetDB) FindEntityById(id string) (*types.Entity, error) {
	return as.Repo.FindEntityById(id)
}

// FindEntitiesByType finds all entities in the database of the provided asset type and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// It returns the matching entities and an error, if any.
func (as *AssetDB) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	return as.Repo.FindEntitiesByType(atype, since)
}

// Link creates an edge between two entities in the database.
// The link is established by creating a new Edge in the database, linking the two entities.
// Returns the created edge as a types.Edge or an error if the link creation fails.
func (as *AssetDB) Link(edge *types.Edge) (*types.Edge, error) {
	return as.Repo.Link(edge)
}

// IncomingEdges finds all edges pointing to the entity for the specified labels, if any.
// If since.IsZero(), the parameter will be ignored.
// If no labels are specified, all incoming edges are returned.
func (as *AssetDB) IncomingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	return as.Repo.IncomingEdges(entity, since, labels...)
}

// OutgoingEdges finds all edges from entity to another entity for the specified labels, if any.
// If since.IsZero(), the parameter will be ignored.
// If no labels are specified, all outgoing edges are returned.
func (as *AssetDB) OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	return as.Repo.OutgoingEdges(entity, since, labels...)
}

// CreateEntityTag creates a new entity tag in the database.
// It takes an oam.Property as input and persists it in the database.
// The entity tag is serialized to JSON and stored in the Content field of the EntityTag struct.
// Returns the created entity tag as a types.EntityTag or an error if the creation fails.
func (as *AssetDB) CreateEntityTag(entity *types.Entity, property oam.Property) (*types.EntityTag, error) {
	return as.Repo.CreateEntityTag(entity, property)
}

// GetEntityTags finds all tags for the entity with the specified names and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no names are specified, all tags for the specified entity are returned.
func (as *AssetDB) GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	return as.Repo.GetEntityTags(entity, since, names...)
}

// DeleteEntityTag removes an entity tag in the database by its ID.
// It takes a string representing the entity tag ID and removes the corresponding tag from the database.
// Returns an error if the tag is not found.
func (as *AssetDB) DeleteEntityTag(id string) error {
	return as.Repo.DeleteEntityTag(id)
}

// CreateEdgeTag creates a new edge tag in the database.
// It takes an oam.Property as input and persists it in the database.
// The edge tag is serialized to JSON and stored in the Content field of the EdgeTag struct.
// Returns the created edge tag as a types.EdgeTag or an error if the creation fails.
func (as *AssetDB) CreateEdgeTag(edge *types.Edge, property oam.Property) (*types.EdgeTag, error) {
	return as.Repo.CreateEdgeTag(edge, property)
}

// GetEdgeTags finds all tags for the edge with the specified names and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no names are specified, all tags for the specified edge are returned.
func (as *AssetDB) GetEdgeTags(edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {
	return as.Repo.GetEdgeTags(edge, since, names...)
}

// DeleteEdgeTag removes an edge tag in the database by its ID.
// It takes a string representing the edge tag ID and removes the corresponding tag from the database.
// Returns an error if the tag is not found.
func (as *AssetDB) DeleteEdgeTag(id string) error {
	return as.Repo.DeleteEdgeTag(id)
}
