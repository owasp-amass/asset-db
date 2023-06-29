// Package assetdb provides a service to interacting with an asset database.
package assetdb

import (
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

// Create creates a new asset in the database.
// If source is nil, the discovered asset will be created and relation will be ignored
// If source and relation are provided, the asset is created and linked to the source asset using the specified relation.
// It returns the newly created asset and an error, if any.
func (as *AssetDB) Create(source *types.Asset, relation string, discovered oam.Asset) (*types.Asset, error) {
	if source == nil || relation == "" {
		return as.repository.CreateAsset(discovered)
	}

	newAsset, err := as.repository.CreateAsset(discovered)
	if err != nil {
		return nil, err
	}

	_, err = as.repository.Link(source, relation, newAsset)
	if err != nil {
		return nil, err
	}

	return newAsset, nil
}

// FindByContent finds assets in the database based on their content.
// It returns a list of matching assets and an error, if any.
func (as *AssetDB) FindByContent(asset oam.Asset) ([]*types.Asset, error) {
	return as.repository.FindAssetByContent(asset)
}

// FindById finds an asset in the database by its ID.
// It returns the matching asset and an error, if any.
func (as *AssetDB) FindById(id string) (*types.Asset, error) {
	return as.repository.FindAssetById(id)
}

// FindByScope finds assets in the database by applying all the scope constraints provided.
// It returns the matching assets and an error, if any.
func (as *AssetDB) FindByScope(constraints ...oam.Asset) ([]*types.Asset, error) {
	return as.repository.FindAssetByScope(constraints...)
}

// IncomingRelations finds all relations pointing to `asset“ for the specified `relationTypes`, if any.
// If no `relationTypes` are specified, all incoming relations are returned.
func (as *AssetDB) IncomingRelations(asset *types.Asset, relationTypes ...string) ([]*types.Relation, error) {
	return as.repository.IncomingRelations(asset, relationTypes...)
}

// OutgoingRelations finds all relations from `asset“ to another asset for the specified `relationTypes`, if any.
// If no `relationTypes` are specified, all outgoing relations are returned.
func (as *AssetDB) OutgoingRelations(asset *types.Asset, relationTypes ...string) ([]*types.Relation, error) {
	return as.repository.OutgoingRelations(asset, relationTypes...)
}
