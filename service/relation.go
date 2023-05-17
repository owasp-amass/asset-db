package service

import (
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/types"
)

type relationService struct {
	relationRepository repository.RelationRepository
}

func NewRelationService(relationRepository repository.RelationRepository) *relationService {
	return &relationService{
		relationRepository: relationRepository,
	}
}

func (rs *relationService) Insert(relationType string, newAssetId string, srcAssetId string) (types.StoredRelation, error) {
	return rs.relationRepository.Insert(relationType, newAssetId, srcAssetId)
}
