// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
	_, err = suite.db.FindOneEntityByContent(ctx, oam.IPAddress, after, dbt.ContentFilters{
		"address": ipstr,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := suite.db.FindOneEntityByContent(ctx, oam.IPAddress, before, dbt.ContentFilters{
		"address": ipstr,
	})
	assert.NoError(t, err, "Failed to find entity by content for the IPAddress")
	assert.NotNil(t, found, "Entity found by content for the IPAddress should not be nil")

	ip2, ok := found.Asset.(*oamnet.IPAddress)
	assert.True(t, ok, "IPAddress found by content is not of type *oamnet.IPAddress")
	assert.Equal(t, found.ID, ipasset.ID, "IPAddress found by content does not have matching IDs")
	assert.Equal(t, ip2.Address, ip, "IPAddress found by ID does not have a matching Address")
	assert.Equal(t, ip2.Type, iptype, "IPAddress found by ID does not have a matching Type")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.IPAddress, before, dbt.ContentFilters{
		"address": ipstr,
	})
	assert.NoError(t, err, "Failed to find entities by content for the IPAddress")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the IPAddress")
}
