package repository

import "github.com/owasp-amass/asset-db/types"

type AssetRepository interface {
	Insert(asset types.Asset) (types.StoredAsset, error)
	GetById(id int64) (types.StoredAsset, error)
	GetByContent(asset types.Asset) (types.StoredAsset, error)
}

type RelationRepository interface {
	Insert(relationType string, newAssetId string, srcAssetId string) (types.StoredRelation, error)
}
