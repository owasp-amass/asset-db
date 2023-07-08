// Package repository provides a database repository implementation for managing assets and relations.
// It allows creating, retrieving, and linking assets in the database.
package repository

import (
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Repository defines the methods for interacting with the asset database.
// It provides operations for creating, retrieving, and linking assets.
type Repository interface {
	CreateAsset(asset oam.Asset) (*types.Asset, error)
	DeleteAsset(id string) error
	DeleteRelation(id string) error
	FindAssetById(id string, since time.Time) (*types.Asset, error)
	FindAssetByContent(asset oam.Asset, since time.Time) ([]*types.Asset, error)
	FindAssetByType(atype oam.AssetType, since time.Time) ([]*types.Asset, error)
	FindAssetByScope(constraints []oam.Asset, since time.Time) ([]*types.Asset, error)
	Link(source *types.Asset, relation string, destination *types.Asset) (*types.Relation, error)
	IncomingRelations(asset *types.Asset, since time.Time, relationTypes ...string) ([]*types.Relation, error)
	OutgoingRelations(asset *types.Asset, since time.Time, relationTypes ...string) ([]*types.Relation, error)
}
