// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Repository defines the methods for interacting with the asset database.
// It provides operations for creating, retrieving, tagging, linking, and deleting assets.
type Repository interface {
	// Type returns the name of the data store implementing this Repository instance.
	Type() string

	// CreateEntity creates a new entity in the database.
	// It takes an Entity as input and persists it in the database.
	// Returns the created entity as a types.Entity or an error if the creation fails.
	CreateEntity(ctx context.Context, entity *types.Entity) (*types.Entity, error)

	// CreateAsset creates a new entity in the database.
	// It takes an oam.Asset as input and persists it in the database.
	// Returns the created entity as a types.Entity or an error if the creation fails.
	CreateAsset(ctx context.Context, asset oam.Asset) (*types.Entity, error)

	// FindEntityById finds an entity in the database by the ID.
	// It takes a string representing the entity ID and retrieves the corresponding entity from the database.
	// Returns the found entity as a types.Entity or an error if the asset is not found.
	FindEntityById(ctx context.Context, id string) (*types.Entity, error)

	// FindOneEntityByContent finds an entity in the database that matches the provided filters, last seen after
	// the since parameter, and most recent within the limit parameter. It takes an oam.Asset as input and searches
	// for an entity with matching content in the database.
	// If since.IsZero(), the parameter will be ignored.
	// If limit == 0, the parameter with be ignored.
	// Returns a single matching entity as *types.Entity or an error if the search fails.
	FindEntitiesByContent(ctx context.Context, atype oam.AssetType, since time.Time, limit int, filters types.ContentFilters) ([]*types.Entity, error)

	// FindEntitiesByType finds all entities in the database of the provided asset type, last seen
	// after the since parameter, and most recent with the limit parameter.
	// The since parameter is not optional.
	// If limit == 0, the parameter with be ignored.
	// Returns a slice of matching entities as []*types.Entity or an error if the search fails.
	FindEntitiesByType(ctx context.Context, atype oam.AssetType, since time.Time, limit int) ([]*types.Entity, error)

	// DeleteEntity removes an entity in the database by the ID.
	// It takes a string representing the entity ID and removes the corresponding entity from the database.
	// Returns an error if the entity is not found.
	DeleteEntity(ctx context.Context, id string) error

	// CreateEdge creates an edge between two entities in the database.
	// The edge is established by creating a new Edge in the database, linking the two entities.
	// Returns the created edge as a types.Edge or an error if the link creation fails.
	CreateEdge(ctx context.Context, edge *types.Edge) (*types.Edge, error)

	// FindEdgeById finds an edge in the database by the ID.
	// It takes a string representing the edge ID and retrieves the corresponding edge from the database.
	// Returns the found edge as a types.Edge or an error if the relation is not found.
	FindEdgeById(ctx context.Context, id string) (*types.Edge, error)

	// IncomingEdges finds all edges pointing to the entity of the specified labels and last seen after the since parameter.
	// If since.IsZero(), the parameter will be ignored.
	// If no labels are specified, all incoming eges are returned.
	IncomingEdges(ctx context.Context, entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error)

	// OutgoingEdges finds all edges from the entity of the specified labels and last seen after the since parameter.
	// If since.IsZero(), the parameter will be ignored.
	// If no labels are specified, all outgoing edges are returned.
	OutgoingEdges(ctx context.Context, entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error)

	// DeleteEdge removes an edge in the database by its ID.
	// It takes a string representing the edge ID and removes the corresponding edge from the database.
	// Returns an error if the edge is not found.
	DeleteEdge(ctx context.Context, id string) error

	// CreateEntityTag creates a new entity tag in the database.
	// It takes an EntityTag as input and persists it in the database.
	// Returns the created entity tag as a types.EntityTag or an error if the creation fails.
	CreateEntityTag(ctx context.Context, entity *types.Entity, tag *types.EntityTag) (*types.EntityTag, error)

	// CreateEntityProperty creates a new entity tag in the database.
	// It takes an oam.Property as input and persists it in the database.
	// Returns the created entity tag as a types.EntityTag or an error if the creation fails.
	CreateEntityProperty(ctx context.Context, entity *types.Entity, property oam.Property) (*types.EntityTag, error)

	// FindEntityTagById finds an entity tag in the database by the ID.
	// It takes a string representing the entity tag ID and retrieves the corresponding tag from the database.
	// Returns the discovered tag as a types.EntityTag or an error if the asset is not found.
	FindEntityTagById(ctx context.Context, id string) (*types.EntityTag, error)

	// FindEntityTags finds all tags for the entity with the specified names and last seen after the since parameter.
	// If since.IsZero(), the parameter will be ignored.
	// If no names are specified, all tags for the specified entity are returned.
	FindEntityTags(ctx context.Context, entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error)

	// DeleteEntityTag removes an entity tag in the database by its ID.
	// It takes a string representing the entity tag ID and removes the corresponding tag from the database.
	// Returns an error if the tag is not found.
	DeleteEntityTag(ctx context.Context, id string) error

	// CreateEdgeTag creates a new edge tag in the database.
	// It takes an EdgeTag as input and persists it in the database.
	// Returns the created edge tag as a types.EdgeTag or an error if the creation fails.
	CreateEdgeTag(ctx context.Context, edge *types.Edge, tag *types.EdgeTag) (*types.EdgeTag, error)

	// CreateEdgeProperty creates a new edge tag in the database.
	// It takes an oam.Property as input and persists it in the database.
	// Returns the created edge tag as a types.EdgeTag or an error if the creation fails.
	CreateEdgeProperty(ctx context.Context, edge *types.Edge, property oam.Property) (*types.EdgeTag, error)

	// FindEdgeTagById finds an edge tag in the database by the ID.
	// It takes a string representing the edge tag ID and retrieves the corresponding tag from the database.
	// Returns the discovered tag as a types.EdgeTag or an error if the asset is not found.
	FindEdgeTagById(ctx context.Context, id string) (*types.EdgeTag, error)

	// FindEdgeTags finds all tags for the edge with the specified names and last seen after the since parameter.
	// If since.IsZero(), the parameter will be ignored.
	// If no names are specified, all tags for the specified edge are returned.
	FindEdgeTags(ctx context.Context, edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error)

	// DeleteEdgeTag removes an edge tag in the database by its ID.
	// It takes a string representing the edge tag ID and removes the corresponding tag from the database.
	// Returns an error if the tag is not found.
	DeleteEdgeTag(ctx context.Context, id string) error

	// Close terminates connections to the database and cleans up allocated resources.
	// Returns an error if unable to cleanly perform the process.
	Close() error
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (Repository, error) {
	switch strings.ToLower(dbtype) {
	case strings.ToLower(neo4j.Neo4j):
		return neo4j.New(dbtype, dsn)
	case strings.ToLower(postgres.Postgres):
		return postgres.New(dbtype, dsn)
	case strings.ToLower(sqlite3.SQLite):
		fallthrough
	case strings.ToLower(sqlite3.SQLiteMemory):
		return sqlite3.New(dbtype, dsn)
	}
	return nil, fmt.Errorf("unknown DB type: %s", dbtype)
}
