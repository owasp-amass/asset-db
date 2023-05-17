package service

import (
	"strconv"

	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/types"
)

// assetService is a struct that implements the AssetService interface.
// It has a dependency on the AssetRepository and RelationService interfaces
// and it's the layer that handles the business logic of the amass application
type assetService struct {
	assetRepository repository.AssetRepository
	relationService RelationService
}

// NewAssetService is a function that returns a new assetService
func NewAssetService(assetRepository repository.AssetRepository, relationService RelationService) *assetService {
	return &assetService{
		assetRepository: assetRepository,
		relationService: relationService,
	}
}

// Insert is a method that inserts a new asset in the database.
// It receives an asset, a source asset and a relation type,
// it inserts the asset in the database, creates a relation between the two assets
// and returns a new asset and an error if it exists
func (as *assetService) Insert(asset types.Asset, srcAsset *types.StoredAsset, relationType *string) (types.StoredAsset, error) {
	if srcAsset == nil || relationType == nil {
		return as.assetRepository.Insert(asset)
	}

	newAsset, err := as.assetRepository.Insert(asset)
	if err != nil {
		return types.StoredAsset{}, err
	}

	_, err = as.relationService.Insert(*relationType, newAsset.ID, srcAsset.ID)
	if err != nil {
		return types.StoredAsset{}, err
	}

	return newAsset, nil
}

func (as *assetService) Exist(asset types.Asset) (bool, error) {
	storedAsset, err := as.GetByContent(asset)
	if err != nil {
		return false, err
	}

	return storedAsset.ID != "", nil
}

func (as *assetService) GetByContent(asset types.Asset) (types.StoredAsset, error) {
	return as.assetRepository.GetByContent(asset)
}

func (as *assetService) GetById(id string) (types.StoredAsset, error) {
	assetId, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return types.StoredAsset{}, err
	}

	return as.assetRepository.GetById(assetId)
}
