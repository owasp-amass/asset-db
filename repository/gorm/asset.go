package gorm

import (
	"strconv"

	"github.com/owasp-amass/asset-db/types"

	"gorm.io/gorm"
)

type assetRepository struct {
	db *gorm.DB
}

func NewAssetRepository(db *gorm.DB) *assetRepository {
	return &assetRepository{
		db: db,
	}
}

func (ar *assetRepository) Insert(assetData types.Asset) (types.StoredAsset, error) {
	jsonContent, err := assetData.JSON()
	if err != nil {
		return types.StoredAsset{}, err
	}

	asset := Asset{
		Type:    string(assetData.AssetType()),
		Content: jsonContent,
	}

	result := ar.db.Create(&asset)
	if result.Error != nil {
		return types.StoredAsset{}, result.Error
	}

	return types.StoredAsset{
		ID:    strconv.FormatInt(asset.ID, 10),
		Asset: assetData,
	}, nil
}

func (ar *assetRepository) GetByContent(assetData types.Asset) (types.StoredAsset, error) {
	jsonContent, err := assetData.JSON()
	if err != nil {
		return types.StoredAsset{}, err
	}

	asset := Asset{
		Type:    string(assetData.AssetType()),
		Content: jsonContent,
	}

	jsonQuery, err := asset.GetJSONQuery()
	if err != nil {
		return types.StoredAsset{}, err
	}

	result := ar.db.First(&asset, jsonQuery)
	if result.Error != nil {
		return types.StoredAsset{}, result.Error
	}

	return types.StoredAsset{
		ID:    strconv.FormatInt(asset.ID, 10),
		Asset: assetData,
	}, nil
}

func (ar *assetRepository) GetById(assetId int64) (types.StoredAsset, error) {
	asset := Asset{ID: assetId}
	result := ar.db.First(&asset)
	if result.Error != nil {
		return types.StoredAsset{}, result.Error
	}

	assetData, err := asset.Parse()
	if err != nil {
		return types.StoredAsset{}, err
	}

	return types.StoredAsset{
		ID:    strconv.FormatInt(asset.ID, 10),
		Asset: assetData,
	}, nil
}
