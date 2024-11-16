// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"errors"
	"strings"
	"time"

	"github.com/owasp-amass/asset-db/repository/sqlrepo"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Repository defines the methods for interacting with the asset database.
// It provides operations for creating, retrieving, tagging, and linking assets.
type Repository interface {
	GetDBType() string
	CreateEntity(asset oam.Asset) (*types.Entity, error)
	UpdateEntityLastSeen(id string) error
	DeleteEntity(id string) error
	FindEntityById(id string) (*types.Entity, error)
	FindEntityByContent(asset oam.Asset, since time.Time) ([]*types.Entity, error)
	FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error)
	Link(edge *types.Edge) (*types.Edge, error)
	FindEdgeById(id string) (*types.Edge, error)
	IncomingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error)
	OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error)
	DeleteEdge(id string) error
	CreateEntityTag(entity *types.Entity, property oam.Property) (*types.EntityTag, error)
	FindEntityTagById(id string) (*types.EntityTag, error)
	GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error)
	DeleteEntityTag(id string) error
	CreateEdgeTag(edge *types.Edge, property oam.Property) (*types.EdgeTag, error)
	FindEdgeTagById(id string) (*types.EdgeTag, error)
	GetEdgeTags(edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error)
	DeleteEdgeTag(id string) error
	Close() error
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (Repository, error) {
	switch strings.ToLower(dbtype) {
	case strings.ToLower(sqlrepo.Postgres):
		fallthrough
	case strings.ToLower(sqlrepo.SQLite):
		fallthrough
	case strings.ToLower(sqlrepo.SQLiteMemory):
		return sqlrepo.New(dbtype, dsn)
	}
	return nil, errors.New("unknown DB type")
}
