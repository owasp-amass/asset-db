// Package assetdb provides a service to interacting with an asset database.
package assetdb

import (
	"time"

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

// GetDBType returns the type of the underlying database.
func (as *AssetDB) GetDBType() string {
	return as.repository.GetDBType()
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

// DeleteAsset removes an asset in the database by its ID.
func (as *AssetDB) DeleteAsset(id string) error {
	return as.repository.DeleteAsset(id)
}

// DeleteRelation removes a relation in the database by its ID.
func (as *AssetDB) DeleteRelation(id string) error {
	return as.repository.DeleteRelation(id)
}

// FindByContent finds assets in the database based on their content and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// It returns a list of matching assets and an error, if any.
func (as *AssetDB) FindByContent(asset oam.Asset, since time.Time) ([]*types.Asset, error) {
	return as.repository.FindAssetByContent(asset, since)
}

// FindById finds an asset in the database by its ID and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// It returns the matching asset and an error, if any.
func (as *AssetDB) FindById(id string, since time.Time) (*types.Asset, error) {
	return as.repository.FindAssetById(id, since)
}

// FindByScope finds assets in the database by applying all the scope constraints provided
// and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// It returns the matching assets and an error, if any.
func (as *AssetDB) FindByScope(constraints []oam.Asset, since time.Time) ([]*types.Asset, error) {
	return as.repository.FindAssetByScope(constraints, since)
}

// FindByType finds all assets in the database of the provided asset type and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// It returns the matching assets and an error, if any.
func (as *AssetDB) FindByType(atype oam.AssetType, since time.Time) ([]*types.Asset, error) {
	return as.repository.FindAssetByType(atype, since)
}

// IncomingRelations finds all relations pointing to `asset“ for the specified `relationTypes`, if any.
// If since.IsZero(), the parameter will be ignored.
// If no `relationTypes` are specified, all incoming relations are returned.
func (as *AssetDB) IncomingRelations(asset *types.Asset, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	return as.repository.IncomingRelations(asset, since, relationTypes...)
}

// OutgoingRelations finds all relations from `asset“ to another asset for the specified `relationTypes`, if any.
// If since.IsZero(), the parameter will be ignored.
// If no `relationTypes` are specified, all outgoing relations are returned.
func (as *AssetDB) OutgoingRelations(asset *types.Asset, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	return as.repository.OutgoingRelations(asset, since, relationTypes...)
}

// RawQuery executes a query defined by the provided sqlstr on the asset-db.
// The results of the executed query are scanned into the provided slice.
func (as *AssetDB) RawQuery(sqlstr string, results interface{}) error {
	return as.repository.RawQuery(sqlstr, results)
}

// AssetQuery executes a query against the asset table of the db.
// For SQL databases, the query will start with "SELECT assets.id, assets.create_at, assets.last_seen, assets.type, assets.content FROM " and then add the necessary constraints.
func (as *AssetDB) AssetQuery(constraints string) ([]*types.Asset, error) {
	return as.repository.AssetQuery(constraints)
}

// RelationQuery executes a query against the relation table of the db.
// The fillFrom and fillTo parameters determine whether the source and destination assets of the relation should be filled.
// For SQL databases, the query will start with "SELECT relations.id, relations.create_at, relations.last_seen, relations.type, relations.from_asset_id, relations.to_asset_id FROM " and then add the necessary constraints.
func (as *AssetDB) RelationQuery(constraints string, fillFrom, fillTo bool) ([]*types.Relation, error) {
	return as.repository.RelationQuery(constraints, fillFrom, fillTo)
}
