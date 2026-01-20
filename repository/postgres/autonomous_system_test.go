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
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresAutonomousSystemTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
	ctx       context.Context
}

func TestPostgresAutonomousSystemTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresAutonomousSystemTestSuite))
}

func (suite *PostgresAutonomousSystemTestSuite) SetupSuite() {
	var err error
	suite.ctx = context.Background()
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresAutonomousSystemTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(suite.ctx); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresAutonomousSystemTestSuite) TestCreateAssetForAutonomousSystem() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	number := 26808
	asn, err := suite.db.CreateAsset(ctx, &oamnet.AutonomousSystem{Number: number})
	assert.NoError(t, err, "Failed to create asset for the AutonomousSystem")
	assert.NotNil(t, asn, "Entity for the AutonomousSystem should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, asn.CreatedAt, before, after, "AutonomousSystem entity CreatedAt is incorrect")
	assert.WithinRange(t, asn.LastSeen, before, after, "AutonomousSystem entity LastSeen is incorrect")

	id, err := strconv.ParseInt(asn.ID, 10, 64)
	assert.NoError(t, err, "AutonomousSystem entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "AutonomousSystem entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, asn.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the AutonomousSystem")
	assert.NotNil(t, found, "Entity found by ID for the AutonomousSystem should not be nil")
	assert.Equal(t, asn.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the AutonomousSystem does not match")
	assert.Equal(t, asn.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the AutonomousSystem does not match")

	asn2, ok := found.Asset.(*oamnet.AutonomousSystem)
	assert.True(t, ok, "Asset found by ID is not of type *oamnet.AutonomousSystem")
	assert.Equal(t, found.ID, asn.ID, "AutonomousSystem found by Entity ID does not have matching IDs")
	assert.Equal(t, asn2.Number, number, "AutonomousSystem found by ID does not have matching number")

	err = suite.db.DeleteEntity(ctx, asn.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the AutonomousSystem")

	_, err = suite.db.FindEntityById(ctx, asn.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the AutonomousSystem")
}

func (suite *PostgresAutonomousSystemTestSuite) TestFindEntitiesByContentForAutonomousSystem() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	number := 26808
	asn, err := suite.db.CreateAsset(ctx, &oamnet.AutonomousSystem{Number: number})
	assert.NoError(t, err, "Failed to create asset for the AutonomousSystem")
	assert.NotNil(t, asn, "Entity for the AutonomousSystem should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindEntitiesByContent(ctx, oam.AutonomousSystem, after, 1, dbt.ContentFilters{
		"number": number,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.AutonomousSystem, before, 1, dbt.ContentFilters{
		"number": number,
	})
	assert.NoError(t, err, "Failed to find entity by content for the AutonomousSystem")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the AutonomousSystem should not be nil")

	asn2, ok := found.Asset.(*oamnet.AutonomousSystem)
	assert.True(t, ok, "AutonomousSystem found by content is not of type *oamnet.AutonomousSystem")
	assert.Equal(t, found.ID, asn.ID, "AutonomousSystem found by content does not have matching IDs")
	assert.Equal(t, asn2.Number, number, "AutonomousSystem Number found by content does not match")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.AutonomousSystem, before, 0, dbt.ContentFilters{
		"number": number,
	})
	assert.NoError(t, err, "Failed to find entities by content for the AutonomousSystem")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the AutonomousSystem")
}

func (suite *PostgresAutonomousSystemTestSuite) TestFindEntitiesByTypeForAutonomousSystem() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key1 := "12345"
	number := 12345
	atype := oam.AutonomousSystem
	atypestr := "AutonomousSystem"
	ent, err := suite.db.CreateAsset(ctx, &oamnet.AutonomousSystem{Number: number})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := "67890"
	number = 67890
	ent, err = suite.db.CreateAsset(ctx, &oamnet.AutonomousSystem{Number: number})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "123890"
	number = 123890
	ent, err = suite.db.CreateAsset(ctx, &oamnet.AutonomousSystem{Number: number})
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
