package repository

import (
	"strconv"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"

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

// Link creates a relation between two assets in the database.
// It takes the source asset, relation type, and destination asset as inputs.
// The relation is established by creating a new Relation struct in the database, linking the two assets.
// Returns the created relation as a types.Relation or an error if the link creation fails.
func (sql *sqlRepository) Link(source *types.Asset, relation string, destination *types.Asset) (*types.Relation, error) {
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
