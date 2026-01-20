// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"log"
	"strconv"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/repository/postgres/testhelpers"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresServiceTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresServiceTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresServiceTestSuite))
}

func (suite *PostgresServiceTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresServiceTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresServiceTestSuite) TestCreateAssetForService() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uniqueID := "fake unique id"
	stype := "Fake Service Type"
	output := "This is a fake service used for testing purposes."
	outlen := len(output)
	attributes := map[string][]string{ // html headers
		"X-Fake-Header": {"FakeHeaderValue1", "FakeHeaderValue2"},
	}

	service, err := suite.db.CreateAsset(ctx, &oamplat.Service{
		ID:         uniqueID,
		Type:       stype,
		Output:     output,
		OutputLen:  outlen,
		Attributes: attributes,
	})
	assert.NoError(t, err, "Failed to create asset for the Service")
	assert.NotNil(t, service, "Entity for the Service should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, service.CreatedAt, before, after, "Service entity CreatedAt is incorrect")
	assert.WithinRange(t, service.LastSeen, before, after, "Service entity LastSeen is incorrect")

	id, err := strconv.ParseInt(service.ID, 10, 64)
	assert.NoError(t, err, "Service entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Service entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, service.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Service")
	assert.NotNil(t, found, "Entity found by ID for the Service should not be nil")
	assert.Equal(t, service.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Service does not match")
	assert.Equal(t, service.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Service does not match")

	service2, ok := found.Asset.(*oamplat.Service)
	assert.True(t, ok, "Service found by ID is not of type *oamplat.Service")
	assert.Equal(t, found.ID, service.ID, "Service found by Entity ID does not have matching IDs")
	assert.Equal(t, service2.ID, uniqueID, "Service found by ID does not have matching UniqueID")
	assert.Equal(t, service2.Type, stype, "Service found by ID does not have matching Type")
	assert.Equal(t, service2.Output, output, "Service found by ID does not have matching Output")
	assert.Equal(t, service2.OutputLen, outlen, "Service found by ID does not have matching OutputLen")
	assert.Equal(t, service2.Attributes, attributes, "Service found by ID does not have matching Attributes")

	err = suite.db.DeleteEntity(ctx, service.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Service")

	_, err = suite.db.FindEntityById(ctx, service.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Service")
}

func (suite *PostgresServiceTestSuite) TestFindEntitiesByContentForService() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uniqueID := "fake unique id"
	stype := "Fake Service Type"
	output := "This is a fake service used for testing purposes."
	outlen := len(output)
	attributes := map[string][]string{ // html headers
		"X-Fake-Header": {"FakeHeaderValue1", "FakeHeaderValue2"},
	}

	service, err := suite.db.CreateAsset(ctx, &oamplat.Service{
		ID:         uniqueID,
		Type:       stype,
		Output:     output,
		OutputLen:  outlen,
		Attributes: attributes,
	})
	assert.NoError(t, err, "Failed to create asset for the Service")
	assert.NotNil(t, service, "Entity for the Service should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindEntitiesByContent(ctx, oam.Service, after, 1, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.Service, before, 1, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Service")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the Service should not be nil")

	service2, ok := found.Asset.(*oamplat.Service)
	assert.True(t, ok, "Service found by content is not of type *oamplat.Service")
	assert.Equal(t, found.ID, service.ID, "Service found by content does not have matching IDs")
	assert.Equal(t, service2.ID, uniqueID, "Service found by content does not have matching unique ID")
	assert.Equal(t, service2.Type, stype, "Service found by content does not have matching type")
	assert.Equal(t, service2.Output, output, "Service found by content does not have matching output")
	assert.Equal(t, service2.OutputLen, outlen, "Service found by content does not have matching output length")
	assert.Equal(t, service2.Attributes, attributes, "Service found by content does not have matching attributes")

	for k, v := range map[string]string{
		"unique_id":    uniqueID,
		"service_type": stype,
	} {
		ents, err := suite.db.FindEntitiesByContent(ctx, oam.Service, before, 0, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the Service")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Service")
	}
}

func (suite *PostgresServiceTestSuite) TestFindEntitiesByTypeForService() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key1 := "Fake1"
	atype := oam.Service
	atypestr := "Service"
	ent, err := suite.db.CreateAsset(ctx, &oamplat.Service{
		ID:   key1,
		Type: "fake type 1",
	})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := "Fake2"
	ent, err = suite.db.CreateAsset(ctx, &oamplat.Service{
		ID:   key2,
		Type: "fake type 2",
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "Fake3"
	ent, err = suite.db.CreateAsset(ctx, &oamplat.Service{
		ID:   key3,
		Type: "fake type 3",
	})
	assert.NoError(t, err, "Failed to create asset for the third %s", atypestr)
	assert.NotNil(t, ent, "Entity for the third %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after23 := time.Now()

	for k, v := range map[string]struct {
		since    time.Time
		limit    int
		expected []string
	}{
		"find all since1": {
			since:    since1,
			limit:    3,
			expected: []string{key3, key2, key1},
		},
		"one out of all": {
			since:    since1,
			limit:    1,
			expected: []string{key3},
		},
		"two out of all": {
			since:    since1,
			limit:    2,
			expected: []string{key3, key2},
		},
		"find all after1": {
			since:    after1,
			limit:    3,
			expected: []string{key3, key2},
		},
		"one out of two and three": {
			since:    since23,
			limit:    1,
			expected: []string{key3},
		},
		"zero entities after23": {
			since:    after23,
			limit:    3,
			expected: []string{},
		},
		"no since returns error": {
			since:    time.Time{},
			limit:    0,
			expected: []string{},
		},
	} {
		ents, err := suite.db.FindEntitiesByType(ctx, atype, v.since, v.limit)

		var got []string
		for _, ent := range ents {
			got = append(got, ent.Asset.Key())
		}

		if len(v.expected) > 0 {
			assert.NoError(t, err, "The %s test failed for %s: expected %v: got: %v", k, atypestr, v.expected, got)
		} else {
			assert.Error(t, err, "The %s test failed for %s: zero findings should return an error", k, atypestr)
		}

		assert.Len(t, ents, len(v.expected),
			"The %s test expected to find exactly %d entities for %s: got: %d", k, v.limit, atypestr, len(ents),
		)
	}
}
