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
	oamacct "github.com/owasp-amass/open-asset-model/account"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresAccountTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresAccountTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresAccountTestSuite))
}

func (suite *PostgresAccountTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresAccountTestSuite) TearDownSuite() {
	//logs, _ := suite.container.Logs(context.Background())
	//b, _ := io.ReadAll(logs)
	//log.Printf("Postgres Container Logs:\n%s", string(b))

	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresAccountTestSuite) TestCreateAssetForAccount() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uid := "test-account-uid-12345"
	atype := oamacct.Checking
	username := "testuser"
	balance := 1000.50
	active := true

	acc, err := suite.db.CreateAsset(ctx, &oamacct.Account{
		ID:       uid,
		Type:     atype,
		Username: username,
		Balance:  balance,
		Active:   active,
	})
	assert.NoError(t, err, "Failed to create asset for the account")
	assert.NotNil(t, acc, "Entity for the account should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()
	assert.WithinRange(t, acc.CreatedAt, before, after, "Account entity CreatedAt is incorrect")
	assert.WithinRange(t, acc.LastSeen, before, after, "Account entity LastSeen is incorrect")

	id, err := strconv.ParseInt(acc.ID, 10, 64)
	assert.NoError(t, err, "Account entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Account entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, acc.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the account")
	assert.NotNil(t, found, "Entity found by ID for the account should not be nil")
	assert.Equal(t, acc.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the account does not match")
	assert.Equal(t, acc.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the account does not match")

	acc2, ok := found.Asset.(*oamacct.Account)
	assert.True(t, ok, "Account found by ID is not of type *oamacct.Account")
	assert.Equal(t, acc2.ID, uid, "Account found by Entity ID does not have matching IDs")
	assert.Equal(t, acc2.Type, atype, "Account found by ID does not have matching account types")
	assert.Equal(t, acc2.Username, username, "Account Username found by ID for the account does not match")
	assert.Equal(t, acc2.Balance, balance, "Account Balance found by ID for the account does not match")
	assert.Equal(t, acc2.Active, active, "Account Active found by ID for the account does not match")

	err = suite.db.DeleteEntity(ctx, acc.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the account")

	_, err = suite.db.FindEntityById(ctx, acc.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the account")
}

func (suite *PostgresAccountTestSuite) TestFindEntitiesByContentForAccount() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uid := "test-account-uid-12345"
	atype := oamacct.Checking
	number := "1234567890"
	username := "testuser"
	balance := 1000.50
	active := true

	acc, err := suite.db.CreateAsset(ctx, &oamacct.Account{
		ID:       uid,
		Type:     atype,
		Number:   number,
		Username: username,
		Balance:  balance,
		Active:   active,
	})
	assert.NoError(t, err, "Failed to create asset for the account")
	assert.NotNil(t, acc, "Entity for the account should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindEntitiesByContent(ctx, oam.Account, after, 1, dbt.ContentFilters{
		"username": username,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.Account, before, 1, dbt.ContentFilters{
		"username": username,
	})
	assert.NoError(t, err, "Failed to find entity by content for the account")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the account should not be nil")
	assert.Equal(t, acc.CreatedAt, found.CreatedAt, "Entity CreatedAt found by content for the account does not match")
	assert.Equal(t, acc.LastSeen, found.LastSeen, "Entity LastSeen found by content for the account does not match")

	acc2, ok := found.Asset.(*oamacct.Account)
	assert.True(t, ok, "Account found by content is not of type *oamacct.Account")
	assert.Equal(t, acc2.ID, uid, "Account found by content does not have matching IDs")
	assert.Equal(t, acc2.Type, atype, "Account found by content does not have matching account types")
	assert.Equal(t, acc2.Username, username, "Account Username found by content for the account does not match")
	assert.Equal(t, acc2.Balance, balance, "Account Balance found by content for the account does not match")
	assert.Equal(t, acc2.Active, active, "Account Active found by content for the account does not match")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.Account, before, 0, dbt.ContentFilters{
		"unique_id": uid,
	})
	assert.NoError(t, err, "Failed to find entities by content for the account")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the account")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.Account, before, 0, dbt.ContentFilters{
		"account_type": string(atype),
	})
	assert.NoError(t, err, "Failed to find entities by content for the account")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the account")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.Account, time.Time{}, 0, dbt.ContentFilters{
		"account_number": number,
	})
	assert.NoError(t, err, "Failed to find entities by content for the account")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the account")
}

func (suite *PostgresAccountTestSuite) TestFindEntitiesByTypeForAccount() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key1 := "Fake1"
	atype := oam.Account
	atypestr := "Account"
	ent, err := suite.db.CreateAsset(ctx, &oamacct.Account{
		ID:       key1,
		Type:     oamacct.Checking,
		Username: "caffix",
	})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := "Fake2"
	ent, err = suite.db.CreateAsset(ctx, &oamacct.Account{
		ID:       key2,
		Type:     oamacct.Checking,
		Username: "caffix",
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "Fake3"
	ent, err = suite.db.CreateAsset(ctx, &oamacct.Account{
		ID:       key3,
		Type:     oamacct.Checking,
		Username: "caffix",
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
