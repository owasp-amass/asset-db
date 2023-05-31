// Package assetdb provides a service to interacting with an asset database.
package assetdb

import (
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// assetDB represents the asset database service.
type assetDB struct {
	repository repository.Repository
}

// New creates a new assetDB instance.
// It initializes the asset database with the specified database type and DSN.
func New(dbType repository.DBType, dsn string) *assetDB {
	database := repository.New(dbType, dsn)
	return &assetDB{
		repository: database,
	}
}

// Create creates a new asset in the database.
// If source is nil, the discovered asset will be created and relation will be ignored
// If source and relation are provided, the asset is created and linked to the source asset using the specified relation.
// It returns the newly created asset and an error, if any.
func (as *assetDB) Create(source *types.Asset, relation *string, discovered oam.Asset) (*types.Asset, error) {
	if source == nil || relation == nil {
		return as.repository.CreateAsset(discovered)
	}

	newAsset, err := as.repository.CreateAsset(discovered)
	if err != nil {
		return &types.Asset{}, err
	}

	_, err = as.repository.Link(source, *relation, newAsset)
	if err != nil {
		return &types.Asset{}, err
	}

	return newAsset, nil
}

// FindByContent finds assets in the database based on their content.
// It returns a list of matching assets and an error, if any.
func (as *assetDB) FindByContent(asset oam.Asset) ([]*types.Asset, error) {
	return as.repository.FindAssetByContent(asset)
}

// FindById finds an asset in the database by its ID.
// It returns the matching asset and an error, if any.
func (as *assetDB) FindById(id string) (*types.Asset, error) {
	return as.repository.FindAssetById(id)
}
