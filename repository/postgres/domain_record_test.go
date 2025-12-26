// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresDomainRecordTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresDomainRecordTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresDomainRecordTestSuite))
}

func (suite *PostgresDomainRecordTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresDomainRecordTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresDomainRecordTestSuite) TestCreateAssetForDomainRecord() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	status := []string{"active"}
	objectID := "test object ID"
	rawRecord := "test raw text"
	recordName := "test record name"
	domain := "test.com"
	punycode := "test puny code"
	extension := "com"
	created := time.Now().Add(-24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	updated := time.Now().Add(-1 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	expiration := time.Now().Add(48 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	server := "whois.test.com"
	dr, err := suite.db.CreateAsset(ctx, &oamreg.DomainRecord{
		Raw:            rawRecord,
		ID:             objectID,
		Domain:         domain,
		Punycode:       punycode,
		Name:           recordName,
		Extension:      extension,
		WhoisServer:    server,
		CreatedDate:    created,
		UpdatedDate:    updated,
		ExpirationDate: expiration,
		Status:         status,
	})
	assert.NoError(t, err, "Failed to create asset for the DomainRecord")
	assert.NotNil(t, dr, "Entity for the DomainRecord should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, dr.CreatedAt, before, after, "DomainRecord entity CreatedAt is incorrect")
	assert.WithinRange(t, dr.LastSeen, before, after, "DomainRecord entity LastSeen is incorrect")

	id, err := strconv.ParseInt(dr.ID, 10, 64)
	assert.NoError(t, err, "DomainRecord entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "DomainRecord entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, dr.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the DomainRecord")
	assert.NotNil(t, found, "Entity found by ID for the DomainRecord should not be nil")
	assert.Equal(t, dr.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the DomainRecord does not match")
	assert.Equal(t, dr.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the DomainRecord does not match")

	dr2, ok := found.Asset.(*oamreg.DomainRecord)
	assert.True(t, ok, "Asset found by ID is not of type *oamreg.DomainRecord")
	assert.Equal(t, found.ID, dr.ID, "DomainRecord found by Entity ID does not have matching IDs")
	assert.Equal(t, dr2.Raw, rawRecord, "DomainRecord found by ID does not have a matching Raw record")
	assert.Equal(t, dr2.ID, objectID, "DomainRecord found by ID does not have a matching ID")
	assert.Equal(t, dr2.Domain, domain, "DomainRecord found by ID does not have a matching Domain")
	assert.Equal(t, dr2.Punycode, punycode, "DomainRecord found by ID does not have a matching Punycode")
	assert.Equal(t, dr2.Name, recordName, "DomainRecord found by ID does not have a matching Name")
	assert.Equal(t, dr2.Extension, extension, "DomainRecord found by ID does not have a matching Extension")
	assert.Equal(t, dr2.WhoisServer, server, "DomainRecord found by ID does not have a matching WhoisServer")
	assert.Equal(t, dr2.CreatedDate, created, "DomainRecord found by ID does not have a matching CreatedDate")
	assert.Equal(t, dr2.UpdatedDate, updated, "DomainRecord found by ID does not have a matching UpdatedDate")
	assert.Equal(t, dr2.ExpirationDate, expiration, "DomainRecord found by ID does not have a matching ExpirationDate")
	assert.Equal(t, dr2.Status, status, "DomainRecord found by ID does not have a matching Status")

	err = suite.db.DeleteEntity(ctx, dr.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the DomainRecord")

	_, err = suite.db.FindEntityById(ctx, dr.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the DomainRecord")
}

func (suite *PostgresDomainRecordTestSuite) TestFindEntitiesByContentForDomainRecord() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	status := []string{"active"}
	objectID := "test object ID"
	rawRecord := "test raw text"
	recordName := "test record name"
	domain := "test.com"
	punycode := "test puny code"
	extension := "com"
	created := time.Now().Add(-24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	updated := time.Now().Add(-1 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	expiration := time.Now().Add(48 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	server := "whois.test.com"
	dr, err := suite.db.CreateAsset(ctx, &oamreg.DomainRecord{
		Raw:            rawRecord,
		ID:             objectID,
		Domain:         domain,
		Punycode:       punycode,
		Name:           recordName,
		Extension:      extension,
		WhoisServer:    server,
		CreatedDate:    created,
		UpdatedDate:    updated,
		ExpirationDate: expiration,
		Status:         status,
	})
	assert.NoError(t, err, "Failed to create asset for the DomainRecord")
	assert.NotNil(t, dr, "Entity for the DomainRecord should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindOneEntityByContent(ctx, oam.DomainRecord, after, dbt.ContentFilters{
		"domain": domain,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := suite.db.FindOneEntityByContent(ctx, oam.DomainRecord, before, dbt.ContentFilters{
		"domain": domain,
	})
	assert.NoError(t, err, "Failed to find entity by content for the DomainRecord")
	assert.NotNil(t, found, "Entity found by content for the DomainRecord should not be nil")

	dr2, ok := found.Asset.(*oamreg.DomainRecord)
	assert.True(t, ok, "DomainRecord found by content is not of type *oamreg.DomainRecord")
	assert.Equal(t, found.ID, dr.ID, "DomainRecord found by content does not have matching IDs")
	assert.Equal(t, dr2.Raw, rawRecord, "DomainRecord found by ID does not have a matching Raw record")
	assert.Equal(t, dr2.ID, objectID, "DomainRecord found by ID does not have a matching ID")
	assert.Equal(t, dr2.Domain, domain, "DomainRecord found by ID does not have a matching Domain")
	assert.Equal(t, dr2.Punycode, punycode, "DomainRecord found by ID does not have a matching Punycode")
	assert.Equal(t, dr2.Name, recordName, "DomainRecord found by ID does not have a matching Name")
	assert.Equal(t, dr2.Extension, extension, "DomainRecord found by ID does not have a matching Extension")
	assert.Equal(t, dr2.WhoisServer, server, "DomainRecord found by ID does not have a matching WhoisServer")
	assert.Equal(t, dr2.CreatedDate, created, "DomainRecord found by ID does not have a matching CreatedDate")
	assert.Equal(t, dr2.UpdatedDate, updated, "DomainRecord found by ID does not have a matching UpdatedDate")
	assert.Equal(t, dr2.ExpirationDate, expiration, "DomainRecord found by ID does not have a matching ExpirationDate")
	assert.Equal(t, dr2.Status, status, "DomainRecord found by ID does not have a matching Status")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.DomainRecord, before, dbt.ContentFilters{
		"name": recordName,
	})
	assert.NoError(t, err, "Failed to find entities by content for the DomainRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the DomainRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.DomainRecord, before, dbt.ContentFilters{
		"extension": extension,
	})
	assert.NoError(t, err, "Failed to find entities by content for the DomainRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the DomainRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.DomainRecord, before, dbt.ContentFilters{
		"punycode": punycode,
	})
	assert.NoError(t, err, "Failed to find entities by content for the DomainRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the DomainRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.DomainRecord, time.Time{}, dbt.ContentFilters{
		"id": objectID,
	})
	assert.NoError(t, err, "Failed to find entities by content for the DomainRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the DomainRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.DomainRecord, before, dbt.ContentFilters{
		"whois_server": server,
	})
	assert.NoError(t, err, "Failed to find entities by content for the DomainRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the DomainRecord")
}
