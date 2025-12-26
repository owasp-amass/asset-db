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
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresIPNetRecordTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresIPNetRecordTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresIPNetRecordTestSuite))
}

func (suite *PostgresIPNetRecordTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresIPNetRecordTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresIPNetRecordTestSuite) TestCreateAssetForIPNetRecord() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	raw := "fake ipnet record"
	cidr := netip.MustParsePrefix("72.237.4.0/24")
	handle := "NET-TEST"
	start := netip.MustParseAddr("72.237.4.0")
	end := netip.MustParseAddr("72.237.4.255")
	iptype := "IPv4"
	recname := "Test IPNet Record"
	method := "ALLOCATED"
	country := "US"
	phandle := "NET-PARENT"
	server := "whois.test.net"
	created := time.Now().Add(-24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	updated := time.Now().Add(-1 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	status := []string{"active"}

	ipnet, err := suite.db.CreateAsset(ctx, &oamreg.IPNetRecord{
		Raw:          raw,
		CIDR:         cidr,
		Handle:       handle,
		StartAddress: start,
		EndAddress:   end,
		Type:         iptype,
		Name:         recname,
		Method:       method,
		Country:      country,
		ParentHandle: phandle,
		WhoisServer:  server,
		CreatedDate:  created,
		UpdatedDate:  updated,
		Status:       status,
	})
	assert.NoError(t, err, "Failed to create asset for the IPNetRecord")
	assert.NotNil(t, ipnet, "Entity for the IPNetRecord should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, ipnet.CreatedAt, before, after, "IPNetRecord entity CreatedAt is incorrect")
	assert.WithinRange(t, ipnet.LastSeen, before, after, "IPNetRecord entity LastSeen is incorrect")

	id, err := strconv.ParseInt(ipnet.ID, 10, 64)
	assert.NoError(t, err, "IPNetRecord entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "IPNetRecord entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, ipnet.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the IPNetRecord")
	assert.NotNil(t, found, "Entity found by ID for the IPNetRecord should not be nil")
	assert.Equal(t, ipnet.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the IPNetRecord does not match")
	assert.Equal(t, ipnet.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the IPNetRecord does not match")

	ipnet2, ok := found.Asset.(*oamreg.IPNetRecord)
	assert.True(t, ok, "IPNetRecord found by ID is not of type *oamreg.IPNetRecord")
	assert.Equal(t, found.ID, ipnet.ID, "IPNetRecord found by Entity ID does not have matching IDs")
	assert.Equal(t, ipnet2.Raw, raw, "IPNetRecord found by ID does not have matching raw")
	assert.Equal(t, ipnet2.CIDR, cidr, "IPNetRecord found by ID does not have matching CIDR")
	assert.Equal(t, ipnet2.Handle, handle, "IPNetRecord found by ID does not have matching handle")
	assert.Equal(t, ipnet2.StartAddress, start, "IPNetRecord found by ID does not have matching start address")
	assert.Equal(t, ipnet2.EndAddress, end, "IPNetRecord found by ID does not have matching end address")
	assert.Equal(t, ipnet2.Type, iptype, "IPNetRecord found by ID does not have matching type")
	assert.Equal(t, ipnet2.Name, recname, "IPNetRecord found by ID does not have matching name")
	assert.Equal(t, ipnet2.Method, method, "IPNetRecord found by ID does not have matching method")
	assert.Equal(t, ipnet2.Country, country, "IPNetRecord found by ID does not have matching country")
	assert.Equal(t, ipnet2.ParentHandle, phandle, "IPNetRecord found by ID does not have matching parent handle")
	assert.Equal(t, ipnet2.WhoisServer, server, "IPNetRecord found by ID does not have matching whois_server")
	assert.Equal(t, ipnet2.CreatedDate, created, "IPNetRecord found by ID does not have matching created_date")
	assert.Equal(t, ipnet2.UpdatedDate, updated, "IPNetRecord found by ID does not have matching updated")
	assert.Equal(t, ipnet2.Status, status, "IPNetRecord found by ID does not have matching status")

	err = suite.db.DeleteEntity(ctx, ipnet.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the IPNetRecord")

	_, err = suite.db.FindEntityById(ctx, ipnet.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the IPNetRecord")
}

func (suite *PostgresIPNetRecordTestSuite) TestFindEntitiesByContentForIPNetRecord() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	raw := "fake ipnet record"
	cidr := netip.MustParsePrefix("72.237.4.0/24")
	handle := "NET-TEST"
	start := netip.MustParseAddr("72.237.4.0")
	end := netip.MustParseAddr("72.237.4.255")
	iptype := "IPv4"
	recname := "Test IPNet Record"
	method := "ALLOCATED"
	country := "US"
	phandle := "NET-PARENT"
	server := "whois.test.net"
	created := time.Now().Add(-24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	updated := time.Now().Add(-1 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	status := []string{"active"}

	ipnet, err := suite.db.CreateAsset(ctx, &oamreg.IPNetRecord{
		Raw:          raw,
		CIDR:         cidr,
		Handle:       handle,
		StartAddress: start,
		EndAddress:   end,
		Type:         iptype,
		Name:         recname,
		Method:       method,
		Country:      country,
		ParentHandle: phandle,
		WhoisServer:  server,
		CreatedDate:  created,
		UpdatedDate:  updated,
		Status:       status,
	})
	assert.NoError(t, err, "Failed to create asset for the IPNetRecord")
	assert.NotNil(t, ipnet, "Entity for the IPNetRecord should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindOneEntityByContent(ctx, oam.IPNetRecord, after, dbt.ContentFilters{
		"handle": handle,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := suite.db.FindOneEntityByContent(ctx, oam.IPNetRecord, before, dbt.ContentFilters{
		"handle": handle,
	})
	assert.NoError(t, err, "Failed to find entity by content for the IPNetRecord")
	assert.NotNil(t, found, "Entity found by content for the IPNetRecord should not be nil")

	ipnet2, ok := found.Asset.(*oamreg.IPNetRecord)
	assert.True(t, ok, "IPNetRecord found by content is not of type *oamreg.IPNetRecord")
	assert.Equal(t, found.ID, ipnet.ID, "IPNetRecord found by content does not have matching IDs")
	assert.Equal(t, ipnet2.Raw, raw, "IPNetRecord found by content does not have matching raw")
	assert.Equal(t, ipnet2.CIDR, cidr, "IPNetRecord found by content does not have matching CIDR")
	assert.Equal(t, ipnet2.Handle, handle, "IPNetRecord Handle found by content does not match")
	assert.Equal(t, ipnet2.StartAddress, start, "IPNetRecord StartAddress found by content does not match")
	assert.Equal(t, ipnet2.EndAddress, end, "IPNetRecord EndAddress found by content does not match")
	assert.Equal(t, ipnet2.Type, iptype, "IPNetRecord Type found by content does not match")
	assert.Equal(t, ipnet2.Name, recname, "IPNetRecord Name found by content does not match")
	assert.Equal(t, ipnet2.Method, method, "IPNetRecord Method found by content does not match")
	assert.Equal(t, ipnet2.Country, country, "IPNetRecord Country found by content does not match")
	assert.Equal(t, ipnet2.ParentHandle, phandle, "IPNetRecord ParentHandle found by content does not match")
	assert.Equal(t, ipnet2.WhoisServer, server, "IPNetRecord WhoisServer found by content does not match")
	assert.Equal(t, ipnet2.CreatedDate, created, "IPNetRecord CreatedDate found by content does not match")
	assert.Equal(t, ipnet2.UpdatedDate, updated, "IPNetRecord UpdatedDate found by content does not match")
	assert.Equal(t, ipnet2.Status, status, "IPNetRecord Status found by content does not match")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.IPNetRecord, before, dbt.ContentFilters{
		"cidr": cidr.String(),
	})
	assert.NoError(t, err, "Failed to find entities by content for the IPNetRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the IPNetRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.IPNetRecord, before, dbt.ContentFilters{
		"handle": handle,
	})
	assert.NoError(t, err, "Failed to find entities by content for the IPNetRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the IPNetRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.IPNetRecord, time.Time{}, dbt.ContentFilters{
		"name": recname,
	})
	assert.NoError(t, err, "Failed to find entities by content for the IPNetRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the IPNetRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.IPNetRecord, time.Time{}, dbt.ContentFilters{
		"start_address": start.String(),
	})
	assert.NoError(t, err, "Failed to find entities by content for the IPNetRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the IPNetRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.IPNetRecord, time.Time{}, dbt.ContentFilters{
		"end_address": end.String(),
	})
	assert.NoError(t, err, "Failed to find entities by content for the IPNetRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the IPNetRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.IPNetRecord, time.Time{}, dbt.ContentFilters{
		"whois_server": server,
	})
	assert.NoError(t, err, "Failed to find entities by content for the IPNetRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the IPNetRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.IPNetRecord, time.Time{}, dbt.ContentFilters{
		"parent_handle": phandle,
	})
	assert.NoError(t, err, "Failed to find entities by content for the IPNetRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the IPNetRecord")
}
