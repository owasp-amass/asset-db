// Package repository provides a database repository implementation for managing assets and relations.
// It allows creating, retrieving, and linking assets in the database.
package repository

import (
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Repository defines the methods for interacting with the asset database.
// It provides operations for creating, retrieving, and linking assets.
type Repository interface {
	CreateAsset(asset oam.Asset) (*types.Asset, error)
	FindAssetById(id string) (*types.Asset, error)
	FindAssetByContent(asset oam.Asset) ([]*types.Asset, error)
	Link(source *types.Asset, relation string, destination *types.Asset) (*types.Relation, error)
}
