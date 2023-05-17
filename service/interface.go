package service

import (
	"github.com/owasp-amass/asset-db/types"
)

type AssetService interface {
	Insert(asset types.Asset, srcAsset *types.StoredAsset, relationType string) (types.StoredAsset, error)
	GetById(id int64) (types.StoredAsset, error)
	GetByContent(asset types.Asset) (types.StoredAsset, error)
}

type RelationService interface {
	Insert(relationType string, newAssetId string, srcAssetId string) (types.StoredRelation, error)
}
