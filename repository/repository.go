// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/asset-db/repository/sqlrepo"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Repository defines the methods for interacting with the asset database.
// It provides operations for creating, retrieving, tagging, and linking assets.
type Repository interface {
	GetDBType() string
	CreateEntity(ctx context.Context, entity *types.Entity) (*types.Entity, error)
	CreateAsset(ctx context.Context, asset oam.Asset) (*types.Entity, error)
	FindEntityById(ctx context.Context, id string) (*types.Entity, error)
	FindEntitiesByContent(ctx context.Context, etype string, since time.Time, filters types.ContentFilters) ([]*types.Entity, error)
	FindOneEntityByContent(ctx context.Context, etype string, since time.Time, filters types.ContentFilters) (*types.Entity, error)
	FindEntitiesByType(ctx context.Context, atype oam.AssetType, since time.Time) ([]*types.Entity, error)
	DeleteEntity(ctx context.Context, id string) error
	CreateEdge(ctx context.Context, edge *types.Edge) (*types.Edge, error)
	FindEdgeById(ctx context.Context, id string) (*types.Edge, error)
	IncomingEdges(ctx context.Context, entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error)
	OutgoingEdges(ctx context.Context, entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error)
	DeleteEdge(ctx context.Context, id string) error
	CreateEntityTag(ctx context.Context, entity *types.Entity, tag *types.EntityTag) (*types.EntityTag, error)
	CreateEntityProperty(ctx context.Context, entity *types.Entity, property oam.Property) (*types.EntityTag, error)
	FindEntityTagById(ctx context.Context, id string) (*types.EntityTag, error)
	FindEntityTags(ctx context.Context, entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error)
	DeleteEntityTag(ctx context.Context, id string) error
	CreateEdgeTag(ctx context.Context, edge *types.Edge, tag *types.EdgeTag) (*types.EdgeTag, error)
	CreateEdgeProperty(ctx context.Context, edge *types.Edge, property oam.Property) (*types.EdgeTag, error)
	FindEdgeTagById(ctx context.Context, id string) (*types.EdgeTag, error)
	FindEdgeTags(ctx context.Context, edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error)
	DeleteEdgeTag(ctx context.Context, id string) error
	Close() error
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (Repository, error) {
	switch strings.ToLower(dbtype) {
	case strings.ToLower(neo4j.Neo4j):
		return neo4j.New(dbtype, dsn)
	case strings.ToLower(sqlrepo.Postgres):
		fallthrough
	case strings.ToLower(sqlite3.SQLite):
		fallthrough
	case strings.ToLower(sqlite3.SQLiteMemory):
		return sqlite3.New(dbtype, dsn)
	}
	return nil, errors.New("unknown DB type")
}
