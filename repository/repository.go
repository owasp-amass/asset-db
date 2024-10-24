// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Repository defines the methods for interacting with the asset database.
// It provides operations for creating, retrieving, and linking assets.
type Repository interface {
	GetDBType() string
	CreateEntity(asset oam.Asset) (*types.Entity, error)
	UpdateEntityLastSeen(id string) error
	DeleteEntity(id string) error
	DeleteRelation(id string) error
	FindEntityById(id string, since time.Time) (*types.Entity, error)
	FindEntityByContent(asset oam.Asset, since time.Time) ([]*types.Entity, error)
	FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error)
	FindEntitiesByScope(constraints []oam.Asset, since time.Time) ([]*types.Entity, error)
	Link(source *types.Entity, relation string, destination *types.Entity) (*types.Relation, error)
	IncomingRelations(asset *types.Entity, since time.Time, relationTypes ...string) ([]*types.Relation, error)
	OutgoingRelations(asset *types.Entity, since time.Time, relationTypes ...string) ([]*types.Relation, error)
	Close() error
}
