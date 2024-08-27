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
	CreateAsset(asset oam.Asset) (*types.Asset, error)
	UpdateAssetLastSeen(id string) error
	DeleteAsset(id string) error
	DeleteRelation(id string) error
	FindAssetById(id string, since time.Time) (*types.Asset, error)
	FindAssetByContent(asset oam.Asset, since time.Time) ([]*types.Asset, error)
	FindAssetByType(atype oam.AssetType, since time.Time) ([]*types.Asset, error)
	FindAssetByScope(constraints []oam.Asset, since time.Time) ([]*types.Asset, error)
	Link(source *types.Asset, relation string, destination *types.Asset) (*types.Relation, error)
	IncomingRelations(asset *types.Asset, since time.Time, relationTypes ...string) ([]*types.Relation, error)
	OutgoingRelations(asset *types.Asset, since time.Time, relationTypes ...string) ([]*types.Relation, error)
	RawQuery(sqlstr string, results interface{}) error
	AssetQuery(constraints string) ([]*types.Asset, error)
	RelationQuery(constraints string) ([]*types.Relation, error)
	Close() error
}
