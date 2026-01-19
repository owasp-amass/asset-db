// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"strconv"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	"github.com/stretchr/testify/assert"
)

func TestCreateAssetForAccount(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uid := "test-account-uid-12345"
	atype := oamacct.Checking
	username := "testuser"
	balance := 1000.50
	active := true

	acc, err := db.CreateAsset(ctx, &oamacct.Account{
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

	found, err := db.FindEntityById(ctx, acc.ID)
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

	err = db.DeleteEntity(ctx, acc.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the account")

	_, err = db.FindEntityById(ctx, acc.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the account")
}

func TestFindEntitiesByContentForAccount(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := setupTestDB(SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

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

	acc, err := db.CreateAsset(ctx, &oamacct.Account{
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

	_, err = db.FindEntitiesByContent(ctx, oam.Account, after, 1, dbt.ContentFilters{
		"username": username,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := db.FindEntitiesByContent(ctx, oam.Account, before, 1, dbt.ContentFilters{
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

	ents, err = db.FindEntitiesByContent(ctx, oam.Account, before, 0, dbt.ContentFilters{
		"unique_id": uid,
	})
	assert.NoError(t, err, "Failed to find entities by content for the account")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the account")

	ents, err = db.FindEntitiesByContent(ctx, oam.Account, before, 0, dbt.ContentFilters{
		"account_type": string(atype),
	})
	assert.NoError(t, err, "Failed to find entities by content for the account")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the account")

	ents, err = db.FindEntitiesByContent(ctx, oam.Account, time.Time{}, 0, dbt.ContentFilters{
		"account_number": number,
	})
	assert.NoError(t, err, "Failed to find entities by content for the account")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the account")
}
