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
	"github.com/owasp-amass/open-asset-model/relation"
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
				description:   "successfully create an asset with edge",
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
					Repo: mockAssetDB,
				}

				if tc.expectedError == nil {
					mockAssetDB.On("CreateEntity", tc.discovered).Return(tc.expected, tc.expectedError)
				}

				e := &types.Edge{
					Relation:   relation.SimpleRelation{Name: tc.relation},
					FromEntity: tc.source,
					ToEntity:   tc.expected,
				}

				if tc.source != nil && tc.relation != "" {
					mockAssetDB.On("Link", e).Return(&types.Edge{}, nil)
				}

				result, err := adb.Create(e, tc.discovered)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("FindEntityById", func(t *testing.T) {
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
					Repo: mockAssetDB,
				}

				mockAssetDB.On("FindEntityById", tc.id).Return(tc.expected, tc.expectedError)

				result, err := adb.FindEntityById(tc.id)

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
					Repo: mockAssetDB,
				}

				mockAssetDB.On("FindEntityByContent", tc.asset, tc.since).Return(tc.expected, tc.expectedError)

				result, err := adb.FindByContent(tc.asset, tc.since)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("FindEntitiesByType", func(t *testing.T) {
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
					Repo: mockAssetDB,
				}

				mockAssetDB.On("FindEntitiesByType", tc.atype, start).Return(tc.expected, tc.expectedError)

				result, err := adb.FindEntitiesByType(tc.atype, start)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("IncomingEdges", func(t *testing.T) {
		testCases := []struct {
			description   string
			asset         *types.Entity
			since         time.Time
			relationTypes []string
			expected      []*types.Edge
			expectedError error
		}{
			{
				description:   "successfully find incoming edges",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected: []*types.Edge{
					{
						ID:         "1",
						Relation:   relation.BasicDNSRelation{Name: "ns_record"},
						FromEntity: &types.Entity{ID: "2", Asset: &domain.FQDN{Name: "www.subdomain1.com"}},
						ToEntity:   &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
					},
					{
						ID:         "2",
						Relation:   relation.BasicDNSRelation{Name: "cname_record"},
						FromEntity: &types.Entity{ID: "3", Asset: &domain.FQDN{Name: "www.subdomain2.com"}},
						ToEntity:   &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
					},
				},
				expectedError: nil,
			},
			{
				description:   "error finding incoming edges",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected:      []*types.Edge{},
				expectedError: fmt.Errorf("error finding incoming edges"),
			},
			{
				description:   "incoming edges before since parameter",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				since:         time.Now().Add(time.Minute),
				relationTypes: []string{"ns_record", "cname_record"},
				expected:      []*types.Edge{},
				expectedError: nil,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					Repo: mockAssetDB,
				}

				mockAssetDB.On("IncomingEdges", tc.asset, tc.since, tc.relationTypes).Return(tc.expected, tc.expectedError)

				result, err := adb.IncomingEdges(tc.asset, tc.since, tc.relationTypes...)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("OutgoingEdges", func(t *testing.T) {
		testCases := []struct {
			description   string
			asset         *types.Entity
			since         time.Time
			relationTypes []string
			expected      []*types.Edge
			expectedError error
		}{
			{
				description:   "successfully find outgoing edges",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected: []*types.Edge{
					{
						ID:         "1",
						Relation:   relation.BasicDNSRelation{Name: "ns_record"},
						FromEntity: &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
						ToEntity:   &types.Entity{ID: "2", Asset: &domain.FQDN{Name: "www.subdomain1.com"}},
					},
					{
						ID:         "2",
						Relation:   relation.BasicDNSRelation{Name: "cname_record"},
						FromEntity: &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
						ToEntity:   &types.Entity{ID: "2", Asset: &domain.FQDN{Name: "www.subdomain2.com"}},
					},
				},
				expectedError: nil,
			},
			{
				description:   "error finding outgoing edges",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				since:         start,
				relationTypes: []string{"ns_record", "cname_record"},
				expected:      []*types.Edge{},
				expectedError: fmt.Errorf("error finding outgoing edges"),
			},
			{
				description:   "outgoing edges before since parameter",
				asset:         &types.Entity{ID: "1", Asset: &domain.FQDN{Name: "www.domain.com"}},
				since:         time.Now().Add(time.Minute),
				relationTypes: []string{"ns_record", "cname_record"},
				expected:      []*types.Edge{},
				expectedError: nil,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					Repo: mockAssetDB,
				}

				mockAssetDB.On("OutgoingEdges", tc.asset, tc.since, tc.relationTypes).Return(tc.expected, tc.expectedError)

				result, err := adb.OutgoingEdges(tc.asset, tc.since, tc.relationTypes...)

				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.expectedError, err)

				mockAssetDB.AssertExpectations(t)
			})
		}
	})

	t.Run("DeleteEdge", func(t *testing.T) {
		testCases := []struct {
			description   string
			id            string
			expectedError error
		}{
			{"edge was deleted", "1", nil},
			{"edge was not deleted", "2", fmt.Errorf("edge was not found")},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				mockAssetDB := new(mockAssetDB)
				adb := AssetDB{
					Repo: mockAssetDB,
				}

				mockAssetDB.On("DeleteEdge", tc.id).Return(tc.expectedError)

				err := adb.DeleteEdge(tc.id)

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
					Repo: mockAssetDB,
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

func (m *mockAssetDB) FindEntityById(id string) (*types.Entity, error) {
	args := m.Called(id)
	return args.Get(0).(*types.Entity), args.Error(1)
}

func (m *mockAssetDB) FindEntityByContent(asset oam.Asset, since time.Time) ([]*types.Entity, error) {
	args := m.Called(asset, since)
	return args.Get(0).([]*types.Entity), args.Error(1)
}

func (m *mockAssetDB) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	args := m.Called(atype, since)
	return args.Get(0).([]*types.Entity), args.Error(1)
}

func (m *mockAssetDB) DeleteEntity(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *mockAssetDB) Link(edge *types.Edge) (*types.Edge, error) {
	args := m.Called(edge)
	return args.Get(0).(*types.Edge), args.Error(1)
}

func (m *mockAssetDB) FindEdgeById(id string) (*types.Edge, error) {
	args := m.Called(id)
	return args.Get(0).(*types.Edge), args.Error(1)
}

func (m *mockAssetDB) IncomingEdges(asset *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	args := m.Called(asset, since, labels)
	return args.Get(0).([]*types.Edge), args.Error(1)
}

func (m *mockAssetDB) OutgoingEdges(asset *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	args := m.Called(asset, since, labels)
	return args.Get(0).([]*types.Edge), args.Error(1)
}

func (m *mockAssetDB) DeleteEdge(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *mockAssetDB) CreateEntityTag(entity *types.Entity, property oam.Property) (*types.EntityTag, error) {
	args := m.Called(entity, property)
	return args.Get(0).(*types.EntityTag), args.Error(1)
}

func (m *mockAssetDB) FindEntityTagById(id string) (*types.EntityTag, error) {
	args := m.Called(id)
	return args.Get(0).(*types.EntityTag), args.Error(1)
}

func (m *mockAssetDB) GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	args := m.Called(entity, since, names)
	return args.Get(0).([]*types.EntityTag), args.Error(1)
}

func (m *mockAssetDB) DeleteEntityTag(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *mockAssetDB) CreateEdgeTag(edge *types.Edge, property oam.Property) (*types.EdgeTag, error) {
	args := m.Called(edge, property)
	return args.Get(0).(*types.EdgeTag), args.Error(1)
}

func (m *mockAssetDB) FindEdgeTagById(id string) (*types.EdgeTag, error) {
	args := m.Called(id)
	return args.Get(0).(*types.EdgeTag), args.Error(1)
}

func (m *mockAssetDB) GetEdgeTags(edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {
	args := m.Called(edge, since, names)
	return args.Get(0).([]*types.EdgeTag), args.Error(1)
}

func (m *mockAssetDB) DeleteEdgeTag(id string) error {
	args := m.Called(id)
	return args.Error(0)
}
