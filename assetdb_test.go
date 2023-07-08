package assetdb

import (
	"fmt"
	"os"
	"testing"
	"time"

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

func (m *mockAssetDB) DeleteAsset(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *mockAssetDB) DeleteRelation(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *mockAssetDB) FindAssetById(id string, since time.Time) (*types.Asset, error) {
	args := m.Called(id, since)
	return args.Get(0).(*types.Asset), args.Error(1)
}

func (m *mockAssetDB) FindAssetByContent(asset oam.Asset, since time.Time) ([]*types.Asset, error) {
	args := m.Called(asset, since)
	return args.Get(0).([]*types.Asset), args.Error(1)
}

func (m *mockAssetDB) FindAssetByScope(constraints []oam.Asset, since time.Time) ([]*types.Asset, error) {
	args := m.Called(constraints, since)
	return args.Get(0).([]*types.Asset), args.Error(1)
}

func (m *mockAssetDB) FindAssetByType(atype oam.AssetType, since time.Time) ([]*types.Asset, error) {
	args := m.Called(atype, since)
	return args.Get(0).([]*types.Asset), args.Error(1)
}

func (m *mockAssetDB) Link(source *types.Asset, relation string, destination *types.Asset) (*types.Relation, error) {
	args := m.Called(source, relation, destination)
	return args.Get(0).(*types.Relation), args.Error(1)
}

func (m *mockAssetDB) IncomingRelations(asset *types.Asset, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	args := m.Called(asset, since, relationTypes)
	return args.Get(0).([]*types.Relation), args.Error(1)
}

func (m *mockAssetDB) OutgoingRelations(asset *types.Asset, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	args := m.Called(asset, since, relationTypes)
	return args.Get(0).([]*types.Relation), args.Error(1)
}

func TestMain(m *testing.M) {
	exitVal := m.Run()

	os.Exit(exitVal)
}

func TestAssetDB(t *testing.T) {
	start := time.Now()

	t.Run("Create", func(t *testing.T) {
		relationType := "foo_relation"

		testCases := []struct {
			description   string
			discovered    oam.Asset
			source        *types.Asset
			relation      string
			expected      *types.Asset
			expectedError error
		}{
			{
				description:   "successfully create initial asset",
				discovered:    domain.FQDN{Name: "www.domain.com"},
				source:        nil,
				relation:      "",
				expected:      &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
				expectedError: nil,
			},
			{
				description:   "successfully create an asset with relation",
				discovered:    network.AutonomousSystem{Number: 1},
				source:        &types.Asset{ID: "2", Asset: network.RIROrganization{Name: "RIPE NCC"}},
				relation:      relationType,
				expected:      &types.Asset{ID: "3", Asset: network.AutonomousSystem{Number: 1}},
				expectedError: nil,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				if tc.expectedError == nil {
					mockAssetDB.On("CreateAsset", tc.discovered).Return(tc.expected, tc.expectedError)
				}

				if tc.source != nil && tc.relation != "" {
					mockAssetDB.On("Link", tc.source, tc.relation, tc.expected).Return(&types.Relation{}, nil)
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
			{"an asset is found", "1", &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}}, nil},
			{"an asset is not found", "2", &types.Asset{}, fmt.Errorf("asset not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("FindAssetById", tc.id, start).Return(tc.expected, tc.expectedError)

				result, err := adb.FindById(tc.id, start)

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
			since         time.Time
			expected      []*types.Asset
			expectedError error
		}{
			{"an asset is found", domain.FQDN{Name: "www.domain.com"}, start, []*types.Asset{{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}}}, nil},
			{"an asset is not found", domain.FQDN{Name: "www.domain.com"}, start, []*types.Asset{}, fmt.Errorf("asset not found")},
			{"asset last seen after since", domain.FQDN{Name: "www.domain.com"}, start, []*types.Asset{{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}}}, nil},
			{"asset last seen before since", domain.FQDN{Name: "www.domain.com"}, time.Now(), []*types.Asset{}, fmt.Errorf("asset last seen before since")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("FindAssetByContent", tc.asset, tc.since).Return(tc.expected, tc.expectedError)

				result, err := adb.FindByContent(tc.asset, tc.since)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("FindByScope", func(t *testing.T) {
		testCases := []struct {
			description   string
			assets        []oam.Asset
			expected      []*types.Asset
			expectedError error
		}{
			{"an asset is found", []oam.Asset{domain.FQDN{Name: "domain.com"}}, []*types.Asset{{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}}}, nil},
			{"an asset is not found", []oam.Asset{domain.FQDN{Name: "domain.com"}}, []*types.Asset{}, fmt.Errorf("asset not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("FindAssetByScope", tc.assets, start).Return(tc.expected, tc.expectedError)

				result, err := adb.FindByScope(tc.assets, start)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("FindByType", func(t *testing.T) {
		testCases := []struct {
			description   string
			atype         oam.AssetType
			expected      []*types.Asset
			expectedError error
		}{
			{"an asset is found", oam.FQDN, []*types.Asset{{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}}}, nil},
			{"an asset is not found", oam.FQDN, []*types.Asset{}, fmt.Errorf("asset not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("FindAssetByType", tc.atype, start).Return(tc.expected, tc.expectedError)

				result, err := adb.FindByType(tc.atype, start)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("IncomingRelations", func(t *testing.T) {
		testCases := []struct {
			description   string
			asset         *types.Asset
			since         time.Time
			relationTypes []string
			expected      []*types.Relation
			expectedError error
		}{
			{
				description:   "successfully find incoming relations",
				asset:         &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected: []*types.Relation{
					{
						ID:        "1",
						Type:      "ns_record",
						FromAsset: &types.Asset{ID: "2", Asset: domain.FQDN{Name: "www.subdomain1.com"}},
						ToAsset:   &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
					},
					{
						ID:        "2",
						Type:      "cname_record",
						FromAsset: &types.Asset{ID: "3", Asset: domain.FQDN{Name: "www.subdomain2.com"}},
						ToAsset:   &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
					},
				},
				expectedError: nil,
			},
			{
				description:   "error finding incoming relations",
				asset:         &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected:      []*types.Relation{},
				expectedError: fmt.Errorf("error finding incoming relations"),
			},
			{
				description:   "incoming relations before since parameter",
				asset:         &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
				since:         time.Now().Add(time.Minute),
				relationTypes: []string{"ns_record", "cname_record"},
				expected:      []*types.Relation{},
				expectedError: nil,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("IncomingRelations", tc.asset, tc.since, tc.relationTypes).Return(tc.expected, tc.expectedError)

				result, err := adb.IncomingRelations(tc.asset, tc.since, tc.relationTypes...)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("OutgoingRelations", func(t *testing.T) {
		testCases := []struct {
			description   string
			asset         *types.Asset
			since         time.Time
			relationTypes []string
			expected      []*types.Relation
			expectedError error
		}{
			{
				description:   "successfully find outgoing relations",
				asset:         &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected: []*types.Relation{
					{
						ID:        "1",
						Type:      "ns_record",
						FromAsset: &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
						ToAsset:   &types.Asset{ID: "2", Asset: domain.FQDN{Name: "www.subdomain1.com"}},
					},
					{
						ID:        "2",
						Type:      "cname_record",
						FromAsset: &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
						ToAsset:   &types.Asset{ID: "2", Asset: domain.FQDN{Name: "www.subdomain2.com"}},
					},
				},
				expectedError: nil,
			},
			{
				description:   "error finding outgoing relations",
				asset:         &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected:      []*types.Relation{},
				expectedError: fmt.Errorf("error finding outgoing relations"),
			},
			{
				description:   "outgoing relations before since parameter",
				asset:         &types.Asset{ID: "1", Asset: domain.FQDN{Name: "www.domain.com"}},
				since:         time.Now().Add(time.Minute),
				relationTypes: []string{"ns_record", "cname_record"},
				expected:      []*types.Relation{},
				expectedError: nil,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("OutgoingRelations", tc.asset, tc.since, tc.relationTypes).Return(tc.expected, tc.expectedError)

				result, err := adb.OutgoingRelations(tc.asset, tc.since, tc.relationTypes...)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("DeleteRelation", func(t *testing.T) {
		testCases := []struct {
			description   string
			id            string
			expectedError error
		}{
			{"relation was deleted", "1", nil},
			{"relation was not deleted", "2", fmt.Errorf("relation was not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("DeleteRelation", tc.id).Return(tc.expectedError)

				err := adb.DeleteRelation(tc.id)

				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("DeleteAsset", func(t *testing.T) {
		testCases := []struct {
			description   string
			id            string
			expectedError error
		}{
			{"asset was deleted", "1", nil},
			{"asset was not deleted", "2", fmt.Errorf("asset was not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("DeleteAsset", tc.id).Return(tc.expectedError)

				err := adb.DeleteAsset(tc.id)

				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})
}
