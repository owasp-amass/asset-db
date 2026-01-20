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
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresOrganizationTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresOrganizationTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresOrganizationTestSuite))
}

func (suite *PostgresOrganizationTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresOrganizationTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresOrganizationTestSuite) TestCreateAssetForOrganization() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uniqueID := "fake unique id"
	name := "Fake Organization"
	legalName := "Fake Organization LLC"
	founding := time.Date(2020, time.January, 15, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05")
	jurisdiction := "US-CA"
	registrationID := "1234567890"
	industry := "Technology"
	markets := []string{"Software", "Cloud Services"}
	active := true
	nonProfit := false
	headcount := 250

	org, err := suite.db.CreateAsset(ctx, &oamorg.Organization{
		ID:             uniqueID,
		Name:           name,
		LegalName:      legalName,
		FoundingDate:   founding,
		Jurisdiction:   jurisdiction,
		RegistrationID: registrationID,
		Industry:       industry,
		TargetMarkets:  markets,
		Active:         active,
		NonProfit:      nonProfit,
		Headcount:      headcount,
	})
	assert.NoError(t, err, "Failed to create asset for the Organization")
	assert.NotNil(t, org, "Entity for the Organization should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, org.CreatedAt, before, after, "Organization entity CreatedAt is incorrect")
	assert.WithinRange(t, org.LastSeen, before, after, "Organization entity LastSeen is incorrect")

	id, err := strconv.ParseInt(org.ID, 10, 64)
	assert.NoError(t, err, "Organization entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Organization entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, org.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Organization")
	assert.NotNil(t, found, "Entity found by ID for the Organization should not be nil")
	assert.Equal(t, org.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Organization does not match")
	assert.Equal(t, org.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Organization does not match")

	org2, ok := found.Asset.(*oamorg.Organization)
	assert.True(t, ok, "Organization found by ID is not of type *oamorg.Organization")
	assert.Equal(t, found.ID, org.ID, "Organization found by Entity ID does not have matching IDs")
	assert.Equal(t, org2.ID, uniqueID, "Organization found by ID does not have matching UniqueID")
	assert.Equal(t, org2.Name, name, "Organization found by ID does not have matching Name")
	assert.Equal(t, org2.LegalName, legalName, "Organization found by ID does not have matching LegalName")
	assert.Equal(t, org2.FoundingDate, founding, "Organization found by ID does not have matching FoundingDate")
	assert.Equal(t, org2.Jurisdiction, jurisdiction, "Organization found by ID does not have matching Jurisdiction")
	assert.Equal(t, org2.RegistrationID, registrationID, "Organization found by ID does not have matching RegistrationID")
	assert.Equal(t, org2.Industry, industry, "Organization found by ID does not have matching Industry")
	assert.Equal(t, org2.TargetMarkets, markets, "Organization found by ID does not have matching TargetMarkets")
	assert.Equal(t, org2.Active, active, "Organization found by ID does not have matching Active status")
	assert.Equal(t, org2.NonProfit, nonProfit, "Organization found by ID does not have matching NonProfit status")
	assert.Equal(t, org2.Headcount, headcount, "Organization found by ID does not have matching Headcount")

	err = suite.db.DeleteEntity(ctx, org.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Organization")

	_, err = suite.db.FindEntityById(ctx, org.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Organization")
}

func (suite *PostgresOrganizationTestSuite) TestFindEntitiesByContentForOrganization() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uniqueID := "fake unique id"
	name := "Fake Organization"
	legalName := "Fake Organization LLC"
	founding := time.Date(2020, time.January, 15, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05")
	jurisdiction := "US-CA"
	registrationID := "1234567890"
	industry := "Technology"
	markets := []string{"Software", "Cloud Services"}
	active := true
	nonProfit := false
	headcount := 250

	org, err := suite.db.CreateAsset(ctx, &oamorg.Organization{
		ID:             uniqueID,
		Name:           name,
		LegalName:      legalName,
		FoundingDate:   founding,
		Jurisdiction:   jurisdiction,
		RegistrationID: registrationID,
		Industry:       industry,
		TargetMarkets:  markets,
		Active:         active,
		NonProfit:      nonProfit,
		Headcount:      headcount,
	})
	assert.NoError(t, err, "Failed to create asset for the Organization")
	assert.NotNil(t, org, "Entity for the Organization should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindEntitiesByContent(ctx, oam.Organization, after, 1, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.Organization, before, 1, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Organization")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the Organization should not be nil")

	org2, ok := found.Asset.(*oamorg.Organization)
	assert.True(t, ok, "Organization found by content is not of type *oamorg.Organization")
	assert.Equal(t, found.ID, org.ID, "Organization found by content does not have matching IDs")
	assert.Equal(t, org2.ID, uniqueID, "Organization found by content does not have matching unique ID")
	assert.Equal(t, org2.Name, name, "Organization found by content does not have matching name")
	assert.Equal(t, org2.LegalName, legalName, "Organization found by content does not have matching legal name")
	assert.Equal(t, org2.FoundingDate, founding, "Organization found by content does not have matching founding date")
	assert.Equal(t, org2.Jurisdiction, jurisdiction, "Organization found by content does not have matching jurisdiction")
	assert.Equal(t, org2.RegistrationID, registrationID, "Organization found by content does not have matching registration ID")
	assert.Equal(t, org2.Industry, industry, "Organization found by content does not have matching industry")
	assert.Equal(t, org2.TargetMarkets, markets, "Organization found by content does not have matching target markets")
	assert.Equal(t, org2.Active, active, "Organization found by content does not have matching active status")
	assert.Equal(t, org2.NonProfit, nonProfit, "Organization found by content does not have matching non-profit status")
	assert.Equal(t, org2.Headcount, headcount, "Organization found by content does not have matching headcount")

	for k, v := range map[string]string{
		"unique_id":       uniqueID,
		"name":            name,
		"legal_name":      legalName,
		"jurisdiction":    jurisdiction,
		"registration_id": registrationID,
	} {
		ents, err := suite.db.FindEntitiesByContent(ctx, oam.Organization, before, 0, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the Organization")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Organization")
	}
}

func (suite *PostgresOrganizationTestSuite) TestFindEntitiesByTypeForOrganization() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key1 := "Fake1"
	atype := oam.Organization
	atypestr := "Organization"
	ent, err := suite.db.CreateAsset(ctx, &oamorg.Organization{
		ID:   key1,
		Name: "fake name 1",
	})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := "Fake2"
	ent, err = suite.db.CreateAsset(ctx, &oamorg.Organization{
		ID:   key2,
		Name: "fake name 2",
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "Fake3"
	ent, err = suite.db.CreateAsset(ctx, &oamorg.Organization{
		ID:   key3,
		Name: "fake name 3",
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
