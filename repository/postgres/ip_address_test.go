// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"log"
	"net/netip"
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

type PostgresIPAddressTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresIPAddressTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresIPAddressTestSuite))
}

func (suite *PostgresIPAddressTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresIPAddressTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresIPAddressTestSuite) TestCreateAssetForIPAddress() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	ip := netip.MustParseAddr("192.0.2.1")
	iptype := "IPv4"
	ipasset, err := suite.db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: ip,
		Type:    iptype,
	})
	assert.NoError(t, err, "Failed to create asset for the IPAddress")
	assert.NotNil(t, ipasset, "Entity for the IPAddress should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, ipasset.CreatedAt, before, after, "IPAddress entity CreatedAt is incorrect")
	assert.WithinRange(t, ipasset.LastSeen, before, after, "IPAddress entity LastSeen is incorrect")

	id, err := strconv.ParseInt(ipasset.ID, 10, 64)
	assert.NoError(t, err, "IPAddress entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "IPAddress entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, ipasset.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the IPAddress")
	assert.NotNil(t, found, "Entity found by ID for the IPAddress should not be nil")
	assert.Equal(t, ipasset.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the IPAddress does not match")
	assert.Equal(t, ipasset.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the IPAddress does not match")

	ip2, ok := found.Asset.(*oamnet.IPAddress)
	assert.True(t, ok, "Asset found by ID is not of type *oamnet.IPAddress")
	assert.Equal(t, found.ID, ipasset.ID, "IPAddress found by Entity ID does not have matching IDs")
	assert.Equal(t, ip2.Address, ip, "IPAddress found by ID does not have a matching Address")
	assert.Equal(t, ip2.Type, iptype, "IPAddress found by ID does not have a matching Type")

	err = suite.db.DeleteEntity(ctx, ipasset.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the IPAddress")

	_, err = suite.db.FindEntityById(ctx, ipasset.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the IPAddress")
}

func (suite *PostgresIPAddressTestSuite) TestFindEntitiesByContentForIPAddress() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	ip := netip.MustParseAddr("192.0.2.1")
	iptype := "IPv4"
	ipasset, err := suite.db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: ip,
		Type:    iptype,
	})
	assert.NoError(t, err, "Failed to create asset for the IPAddress")
	assert.NotNil(t, ipasset, "Entity for the IPAddress should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	ipstr := ip.String()
	_, err = suite.db.FindEntitiesByContent(ctx, oam.IPAddress, after, 1, dbt.ContentFilters{
		"address": ipstr,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.IPAddress, before, 1, dbt.ContentFilters{
		"address": ipstr,
	})
	assert.NoError(t, err, "Failed to find entity by content for the IPAddress")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the IPAddress should not be nil")

	ip2, ok := found.Asset.(*oamnet.IPAddress)
	assert.True(t, ok, "IPAddress found by content is not of type *oamnet.IPAddress")
	assert.Equal(t, found.ID, ipasset.ID, "IPAddress found by content does not have matching IDs")
	assert.Equal(t, ip2.Address, ip, "IPAddress found by ID does not have a matching Address")
	assert.Equal(t, ip2.Type, iptype, "IPAddress found by ID does not have a matching Type")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.IPAddress, before, 0, dbt.ContentFilters{
		"address": ipstr,
	})
	assert.NoError(t, err, "Failed to find entities by content for the IPAddress")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the IPAddress")
}

func (suite *PostgresIPAddressTestSuite) TestFindEntitiesByTypeForIPAddress() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	iptype := "IPv4"
	atype := oam.IPAddress
	atypestr := "IPAddress"
	ip := netip.MustParseAddr("192.0.2.1")
	key1 := ip.String()
	ent, err := suite.db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: ip,
		Type:    iptype,
	})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	ip = netip.MustParseAddr("72.128.4.1")
	key2 := ip.String()
	ent, err = suite.db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: ip,
		Type:    iptype,
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	ip = netip.MustParseAddr("150.156.0.1")
	key3 := ip.String()
	ent, err = suite.db.CreateAsset(ctx, &oamnet.IPAddress{
		Address: ip,
		Type:    iptype,
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
