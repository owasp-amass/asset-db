// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

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
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestAssetDB(t *testing.T) {
	start := time.Now()

	t.Run("Create", func(t *testing.T) {
		relationType := "registration"

		testCases := []struct {
			description   string
			discovered    oam.Asset
			source        *types.Entity
			relation      string
			expected      *types.Entity
			expectedError error
		}{
			{
				description:   "successfully create initial asset",
				discovered:    &domain.FQDN{Name: "www.domain.com"},
				source:        nil,
				relation:      "",
				expected:      &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				expectedError: nil,
			},
			{
				description:   "successfully create an asset with relation",
				discovered:    &network.AutonomousSystem{Number: 1},
				source:        &types.Entity{ID: "2", Asset: &oamreg.AutnumRecord{Number: 1, Handle: "AS1"}},
				relation:      relationType,
				expected:      &types.Entity{ID: "3", Asset: &network.AutonomousSystem{Number: 1}},
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
					mockAssetDB.On("CreateEntity", tc.discovered).Return(tc.expected, tc.expectedError)
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
			expected      *types.Entity
			expectedError error
		}{
			{"an entity is found", "1", &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}}, nil},
			{"an entity is not found", "2", &types.Entity{}, fmt.Errorf("asset not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("FindEntityById", tc.id, start).Return(tc.expected, tc.expectedError)

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
			expected      []*types.Entity
			expectedError error
		}{
			{"an entity is found", &domain.FQDN{Name: "www.domain.com"}, start, []*types.Entity{{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}}}, nil},
			{"an entity is not found", &domain.FQDN{Name: "www.domain.com"}, start, []*types.Entity{}, fmt.Errorf("asset not found")},
			{"entity last seen after since", &domain.FQDN{Name: "www.domain.com"}, start, []*types.Entity{{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}}}, nil},
			{"entity last seen before since", &domain.FQDN{Name: "www.domain.com"}, time.Now(), []*types.Entity{}, fmt.Errorf("asset last seen before since")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("FindEntityByContent", tc.asset, tc.since).Return(tc.expected, tc.expectedError)

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
			expected      []*types.Entity
			expectedError error
		}{
			{"an entity is found", []oam.Asset{&domain.FQDN{Name: "domain.com"}}, []*types.Entity{{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}}}, nil},
			{"an entity is not found", []oam.Asset{&domain.FQDN{Name: "domain.com"}}, []*types.Entity{}, fmt.Errorf("entity not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("FindEntitiesByScope", tc.assets, start).Return(tc.expected, tc.expectedError)

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
			expected      []*types.Entity
			expectedError error
		}{
			{"an entity is found", oam.FQDN, []*types.Entity{{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}}}, nil},
			{"an entity is not found", oam.FQDN, []*types.Entity{}, fmt.Errorf("entity not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("FindEntitiesByType", tc.atype, start).Return(tc.expected, tc.expectedError)

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
			asset         *types.Entity
			since         time.Time
			relationTypes []string
			expected      []*types.Relation
			expectedError error
		}{
			{
				description:   "successfully find incoming relations",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected: []*types.Relation{
					{
						ID:         "1",
						Type:       "ns_record",
						FromEntity: &types.Entity{ID: "2", Asset: &domain.FQDN{Name: "www.subdomain1.com"}},
						ToEntity:   &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
					},
					{
						ID:         "2",
						Type:       "cname_record",
						FromEntity: &types.Entity{ID: "3", Asset: &domain.FQDN{Name: "www.subdomain2.com"}},
						ToEntity:   &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
					},
				},
				expectedError: nil,
			},
			{
				description:   "error finding incoming relations",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected:      []*types.Relation{},
				expectedError: fmt.Errorf("error finding incoming relations"),
			},
			{
				description:   "incoming relations before since parameter",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
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
			asset         *types.Entity
			since         time.Time
			relationTypes []string
			expected      []*types.Relation
			expectedError error
		}{
			{
				description:   "successfully find outgoing relations",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected: []*types.Relation{
					{
						ID:         "1",
						Type:       "ns_record",
						FromEntity: &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
						ToEntity:   &types.Entity{ID: "2", Asset: &domain.FQDN{Name: "www.subdomain1.com"}},
					},
					{
						ID:         "2",
						Type:       "cname_record",
						FromEntity: &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
						ToEntity:   &types.Entity{ID: "2", Asset: &domain.FQDN{Name: "www.subdomain2.com"}},
					},
				},
				expectedError: nil,
			},
			{
				description:   "error finding outgoing relations",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected:      []*types.Relation{},
				expectedError: fmt.Errorf("error finding outgoing relations"),
			},
			{
				description:   "outgoing relations before since parameter",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
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
			{"entity was deleted", "1", nil},
			{"entity was not deleted", "2", fmt.Errorf("entity was not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					repository: mockAssetDB,
				}

				mockAssetDB.On("DeleteEntity", tc.id).Return(tc.expectedError)

				err := adb.DeleteEntity(tc.id)

				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})
}

type mockAssetDB struct {
	mock.Mock
}

func (m *mockAssetDB) Close() error {
	return nil
}

func (m *mockAssetDB) GetDBType() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockAssetDB) CreateEntity(asset oam.Asset) (*types.Entity, error) {
	args := m.Called(asset)
	return args.Get(0).(*types.Entity), args.Error(1)
}

func (m *mockAssetDB) UpdateEntityLastSeen(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *mockAssetDB) DeleteEntity(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *mockAssetDB) DeleteRelation(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *mockAssetDB) FindEntityById(id string, since time.Time) (*types.Entity, error) {
	args := m.Called(id, since)
	return args.Get(0).(*types.Entity), args.Error(1)
}

func (m *mockAssetDB) FindEntityByContent(asset oam.Asset, since time.Time) ([]*types.Entity, error) {
	args := m.Called(asset, since)
	return args.Get(0).([]*types.Entity), args.Error(1)
}

func (m *mockAssetDB) FindEntitiesByScope(constraints []oam.Asset, since time.Time) ([]*types.Entity, error) {
	args := m.Called(constraints, since)
	return args.Get(0).([]*types.Entity), args.Error(1)
}

func (m *mockAssetDB) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	args := m.Called(atype, since)
	return args.Get(0).([]*types.Entity), args.Error(1)
}

func (m *mockAssetDB) Link(source *types.Entity, relation string, destination *types.Entity) (*types.Relation, error) {
	args := m.Called(source, relation, destination)
	return args.Get(0).(*types.Relation), args.Error(1)
}

func (m *mockAssetDB) IncomingRelations(asset *types.Entity, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	args := m.Called(asset, since, relationTypes)
	return args.Get(0).([]*types.Relation), args.Error(1)
}

func (m *mockAssetDB) OutgoingRelations(asset *types.Entity, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	args := m.Called(asset, since, relationTypes)
	return args.Get(0).([]*types.Relation), args.Error(1)
}
