package assetdb

import (
	"fmt"
	"os"
	"testing"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockAssetDB struct {
	mock.Mock
}

func (m *mockAssetDB) CreateAsset(asset oam.Asset) (*types.Asset, error) {
	args := m.Called(asset)
	return args.Get(0).(*types.Asset), args.Error(1)
}

func (m *mockAssetDB) FindAssetById(id string) (*types.Asset, error) {
	args := m.Called(id)
	return args.Get(0).(*types.Asset), args.Error(1)
}

func (m *mockAssetDB) FindAssetByContent(asset oam.Asset) ([]*types.Asset, error) {
	args := m.Called(asset)
	return args.Get(0).([]*types.Asset), args.Error(1)
}

func (m *mockAssetDB) Link(source *types.Asset, relation string, destination *types.Asset) (*types.Relation, error) {
	args := m.Called(source, relation, destination)
	return args.Get(0).(*types.Relation), args.Error(1)
}

func TestMain(m *testing.M) {
	exitVal := m.Run()

	os.Exit(exitVal)
}

func TestAssetDB(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		relationType := "foo_relation"

		testCases := []struct {
			description   string
			discovered    oam.Asset
			source        *types.Asset
			relation      *string
			expected      *types.Asset
			expectedError error
		}{
			{
				description:   "successfully create initial asset",
				discovered:    domain.FQDN{Name: "www.domain.com"},
				source:        nil,
				relation:      nil,
				expected:      &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
				expectedError: nil,
			},
			{
				description:   "successfully create an asset with relation",
				discovered:    network.AutonomousSystem{Number: 1},
				source:        &types.Asset{ID: "2", Asset: network.RIROrganization{Name: "RIPE NCC"}},
				relation:      &relationType,
				expected:      &types.Asset{ID: "3", Asset: network.AutonomousSystem{Number: 1}},
				expectedError: nil,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := assetDB{
					repository: mockAssetDB,
				}

				if tc.expectedError == nil {
					mockAssetDB.On("CreateAsset", tc.discovered).Return(tc.expected, tc.expectedError)
				}

				if tc.source != nil && tc.relation != nil {
					mockAssetDB.On("Link", tc.source, *tc.relation, tc.expected).Return(&types.Relation{}, nil)
				}

				result, err := adb.Create(tc.source, tc.relation, tc.discovered)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("FindById", func(t *testing.T) {
		testCases := []struct {
			description   string
			id            string
			expected      *types.Asset
			expectedError error
		}{
			{"An asset is found", "1", &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}}, nil},
			{"An asset is not found", "2", &types.Asset{}, fmt.Errorf("Asset not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := assetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("FindAssetById", tc.id).Return(tc.expected, tc.expectedError)

				result, err := adb.FindById(tc.id)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("FindByContent", func(t *testing.T) {
		testCases := []struct {
			description   string
			asset         oam.Asset
			expected      []*types.Asset
			expectedError error
		}{
			{"An asset is found", domain.FQDN{Name: "www.domain.com"}, []*types.Asset{{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}}}, nil},
			{"An asset is not found", domain.FQDN{Name: "www.domain.com"}, []*types.Asset{}, fmt.Errorf("Asset not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := assetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("FindAssetByContent", tc.asset).Return(tc.expected, tc.expectedError)

				result, err := adb.FindByContent(tc.asset)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})
}
