package gorm

import (
	"strconv"

	"github.com/owasp-amass/asset-db/types"
	"gorm.io/gorm"
)

type relationRepository struct {
	db *gorm.DB
}

func NewRelationRepository(db *gorm.DB) *relationRepository {
	return &relationRepository{
		db: db,
	}
}

func (rr *relationRepository) Insert(relationType string, newAssetId string, srcAssetId string) (types.StoredRelation, error) {
	fromAssetId, err := strconv.ParseInt(srcAssetId, 10, 64)
	if err != nil {
		return types.StoredRelation{}, err
	}

	toAssetId, err := strconv.ParseInt(newAssetId, 10, 64)
	if err != nil {
		return types.StoredRelation{}, err
	}

	relation := Relation{
		Type:        relationType,
		FromAssetID: fromAssetId,
		ToAssetID:   toAssetId,
	}

	result := rr.db.Create(&relation)
	if result.Error != nil {
		return types.StoredRelation{}, result.Error
	}

	return types.StoredRelation{
		ID:          strconv.FormatInt(relation.ID, 10),
		Type:        relation.Type,
		FromAssetID: srcAssetId,
		ToAssetID:   newAssetId,
	}, nil
}
