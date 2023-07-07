package repository

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DBType represents the type of the database.
type DBType string

const (
	// Postgres represents the PostgreSQL database type.
	Postgres DBType = "postgres"
	// SQLite represents the SQLite database type.
	SQLite DBType = "sqlite"
)

// sqlRepository is a repository implementation using GORM as the underlying ORM.
type sqlRepository struct {
	db *gorm.DB
}

// New creates a new instance of the asset database repository.
func New(dbType DBType, dsn string) *sqlRepository {
	db, err := newDatabase(dbType, dsn)
	if err != nil {
		panic(err)
	}

	return &sqlRepository{
		db: db,
	}
}

// newDatabase creates a new GORM database connection based on the provided database type and data source name (dsn).
func newDatabase(dbType DBType, dsn string) (*gorm.DB, error) {
	switch dbType {
	case Postgres:
		return postgresDatabase(dsn)
	case SQLite:
		return sqliteDatabase(dsn)
	default:
		panic("Unknown db type")
	}
}

// postgresDatabase creates a new PostgreSQL database connection using the provided data source name (dsn).
func postgresDatabase(dsn string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
}

// sqliteDatabase creates a new SQLite database connection using the provided data source name (dsn).
func sqliteDatabase(dsn string) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
}

// CreateAsset creates a new asset in the database.
// It takes an oam.Asset as input and persists it in the database.
// The asset is serialized to JSON and stored in the Content field of the Asset struct.
// Returns the created asset as a types.Asset or an error if the creation fails.
func (sql *sqlRepository) CreateAsset(assetData oam.Asset) (*types.Asset, error) {
	// ensure that duplicate relationships are not entered into the database
	if assets, err := sql.FindAssetByContent(assetData); err == nil && len(assets) > 0 {
		for _, a := range assets {
			if assetData.AssetType() == a.Asset.AssetType() {
				return a, nil
			}
		}
	}

	jsonContent, err := assetData.JSON()
	if err != nil {
		return &types.Asset{}, err
	}

	asset := Asset{
		Type:    string(assetData.AssetType()),
		Content: jsonContent,
	}

	result := sql.db.Create(&asset)
	if result.Error != nil {
		return &types.Asset{}, result.Error
	}

	return &types.Asset{
		ID:    strconv.FormatInt(asset.ID, 10),
		Asset: assetData,
	}, nil
}

// DeleteAsset removes an asset in the database by its ID.
// It takes a string representing the asset ID and removes the corresponding asset from the database.
// Returns an error if the asset is not found.
func (sql *sqlRepository) DeleteAsset(id string) error {
	if rels, err := sql.IncomingRelations(&types.Asset{ID: id}); err == nil {
		for _, rel := range rels {
			if err := sql.DeleteRelation(rel.ID); err != nil {
				return err
			}
		}
	}

	if rels, err := sql.OutgoingRelations(&types.Asset{ID: id}); err == nil {
		for _, rel := range rels {
			if err := sql.DeleteRelation(rel.ID); err != nil {
				return err
			}
		}
	}

	assetId, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	asset := Asset{ID: assetId}
	result := sql.db.Delete(&asset)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// DeleteRelation removes a relation in the database by its ID.
// It takes a string representing the relation ID and removes the corresponding relation from the database.
// Returns an error if the relation is not found.
func (sql *sqlRepository) DeleteRelation(id string) error {
	relId, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	relation := Relation{ID: relId}
	result := sql.db.Delete(&relation)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// FindAssetByContent finds assets in the database that match the provided asset data.
// It takes an oam.Asset as input and searches for assets with matching content in the database.
// The asset data is serialized to JSON and compared against the Content field of the Asset struct.
// Returns a slice of matching assets as []*types.Asset or an error if the search fails.
func (sql *sqlRepository) FindAssetByContent(assetData oam.Asset) ([]*types.Asset, error) {
	jsonContent, err := assetData.JSON()
	if err != nil {
		return []*types.Asset{}, err
	}

	asset := Asset{
		Type:    string(assetData.AssetType()),
		Content: jsonContent,
	}

	jsonQuery, err := asset.JSONQuery()
	if err != nil {
		return []*types.Asset{}, err
	}

	var assets []Asset
	result := sql.db.Find(&assets, jsonQuery)
	if result.Error != nil {
		return []*types.Asset{}, result.Error
	}

	var storedAssets []*types.Asset
	for _, asset := range assets {
		assetData, err := asset.Parse()
		if err != nil {
			return []*types.Asset{}, err
		}

		storedAssets = append(storedAssets, &types.Asset{
			ID:    strconv.FormatInt(asset.ID, 10),
			Asset: assetData,
		})
	}

	return storedAssets, nil
}

// FindAssetById finds an asset in the database by its ID.
// It takes a string representing the asset ID and retrieves the corresponding asset from the database.
// Returns the found asset as a types.Asset or an error if the asset is not found.
func (sql *sqlRepository) FindAssetById(id string) (*types.Asset, error) {
	assetId, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return &types.Asset{}, err
	}

	asset := Asset{ID: assetId}
	result := sql.db.First(&asset)
	if result.Error != nil {
		return &types.Asset{}, result.Error
	}

	assetData, err := asset.Parse()
	if err != nil {
		return &types.Asset{}, err
	}

	return &types.Asset{
		ID:    strconv.FormatInt(asset.ID, 10),
		Asset: assetData,
	}, nil
}

// FindAssetByScope finds assets in the database by applying all the scope constraints provided.
// It takes variadic arguments representing the set of constraints to serve as the scope and
// retrieves the corresponding assets from the database.
// Returns a slice of matching assets as []*types.Asset or an error if the search fails.
func (sql *sqlRepository) FindAssetByScope(constraints ...oam.Asset) ([]*types.Asset, error) {
	var names []*types.Asset

	for _, constraint := range constraints {
		fqdn, ok := constraint.(domain.FQDN)
		if !ok {
			continue
		}

		var assets []Asset
		result := sql.db.Where("type = ? AND content->>'name' LIKE ?", oam.FQDN, "%"+fqdn.Name).Find(&assets)
		if result.Error != nil {
			continue
		}

		for _, a := range assets {
			if f, err := a.Parse(); err == nil {
				names = append(names, &types.Asset{
					ID:    strconv.FormatInt(a.ID, 10),
					Asset: f,
				})
			}
		}
	}

	if len(names) == 0 {
		return []*types.Asset{}, errors.New("no assets in scope")
	}
	return names, nil
}

// FindAssetByType finds all assets in the database of the provided asset type.
// It takes an asset type and retrieves the corresponding assets from the database.
// Returns a slice of matching assets as []*types.Asset or an error if the search fails.
func (sql *sqlRepository) FindAssetByType(atype oam.AssetType) ([]*types.Asset, error) {
	var assets []Asset

	res := sql.db.Where(&Asset{Type: string(atype)}).Find(&assets)
	if res.Error != nil {
		return []*types.Asset{}, res.Error
	}

	var results []*types.Asset
	for _, a := range assets {
		if f, err := a.Parse(); err == nil {
			results = append(results, &types.Asset{
				ID:    strconv.FormatInt(a.ID, 10),
				Asset: f,
			})
		}
	}

	if len(results) == 0 {
		return []*types.Asset{}, errors.New("no assets of the specified type")
	}
	return results, nil
}

// Link creates a relation between two assets in the database.
// It takes the source asset, relation type, and destination asset as inputs.
// The relation is established by creating a new Relation struct in the database, linking the two assets.
// Returns the created relation as a types.Relation or an error if the link creation fails.
func (sql *sqlRepository) Link(source *types.Asset, relation string, destination *types.Asset) (*types.Relation, error) {
	// check that this link will create a valid relationship within the taxonomy
	srctype := source.Asset.AssetType()
	destype := destination.Asset.AssetType()
	if !oam.ValidRelationship(srctype, relation, destype) {
		return &types.Relation{}, fmt.Errorf("%s -%s-> %s is not valid in the taxonomy", srctype, relation, destype)
	}

	// ensure that duplicate relationships are not entered into the database
	if rel, found := sql.duplicateLink(source, relation, destination); found {
		return rel, nil
	}

	fromAssetId, err := strconv.ParseInt(source.ID, 10, 64)
	if err != nil {
		return &types.Relation{}, err
	}

	toAssetId, err := strconv.ParseInt(destination.ID, 10, 64)
	if err != nil {
		return &types.Relation{}, err
	}

	r := Relation{
		Type:        relation,
		FromAssetID: fromAssetId,
		ToAssetID:   toAssetId,
	}

	result := sql.db.Create(&r)
	if result.Error != nil {
		return &types.Relation{}, result.Error
	}

	return &types.Relation{
		ID:        strconv.FormatInt(r.ID, 10),
		Type:      r.Type,
		FromAsset: source,
		ToAsset:   destination,
	}, nil
}

func (sql *sqlRepository) duplicateLink(source *types.Asset, relation string, destination *types.Asset) (*types.Relation, bool) {
	var dup bool
	var rel *types.Relation

	if outs, err := sql.OutgoingRelations(source, relation); err == nil {
		for _, out := range outs {
			if destination.ID == out.ToAsset.ID {
				rel = out
				dup = true
				break
			}
		}
	}
	return rel, dup
}

// IncomingRelations finds all relations pointing to the asset for the specified relation types, if any.
// If no relationTypes are specified, all outgoing relations are returned.
func (sql *sqlRepository) IncomingRelations(asset *types.Asset, relationTypes ...string) ([]*types.Relation, error) {
	assetId, err := strconv.ParseInt(asset.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	relations := []Relation{}
	if len(relationTypes) > 0 {
		res := sql.db.Where("to_asset_id = ? AND type IN ?", assetId, relationTypes).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	} else {
		res := sql.db.Where("to_asset_id = ?", assetId).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	}

	return toRelations(relations), nil
}

// OutgoingRelations finds all relations from the asset to another asset for the specified relation types, if any.
// If no relationTypes are specified, all outgoing relations are returned.
func (sql *sqlRepository) OutgoingRelations(asset *types.Asset, relationTypes ...string) ([]*types.Relation, error) {
	assetId, err := strconv.ParseInt(asset.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	relations := []Relation{}
	if len(relationTypes) > 0 {
		res := sql.db.Where("from_asset_id = ? AND type IN ?", assetId, relationTypes).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	} else {
		res := sql.db.Where("from_asset_id = ?", assetId).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	}

	return toRelations(relations), nil
}

// toRelation converts a database Relation to a types.Relation.
func toRelation(r Relation) *types.Relation {
	rel := &types.Relation{
		ID:   strconv.FormatInt(r.ID, 10),
		Type: r.Type,
		FromAsset: &types.Asset{
			ID: strconv.FormatInt(r.FromAssetID, 10),
			// Not joining to Asset to get Content
		},
		ToAsset: &types.Asset{
			ID: strconv.FormatInt(r.ToAssetID, 10),
			// Not joining to Asset to get Content
		},
	}
	return rel
}

// toRelations converts a slice database Relations to a slice of types.Relation structs.
func toRelations(relations []Relation) []*types.Relation {
	var res []*types.Relation

	for _, r := range relations {
		res = append(res, toRelation(r))
	}

	return res
}
