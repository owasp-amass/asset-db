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
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresFundsTransferTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresFundsTransferTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresFundsTransferTestSuite))
}

func (suite *PostgresFundsTransferTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresFundsTransferTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresFundsTransferTestSuite) TestCreateAssetForFundsTransfer() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	unique_id := "test unique ID"
	amount := 1987.65
	refID := "test reference ID"
	currency := "USD"
	method := "wire transfer"
	date := time.Now().Add(-72 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	rate := 1.0

	ft, err := suite.db.CreateAsset(ctx, &oamfin.FundsTransfer{
		ID:              unique_id,
		Amount:          amount,
		ReferenceNumber: refID,
		Currency:        currency,
		Method:          method,
		ExchangeDate:    date,
		ExchangeRate:    rate,
	})
	assert.NoError(t, err, "Failed to create asset for the FundsTransfer")
	assert.NotNil(t, ft, "Entity for the FundsTransfer should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, ft.CreatedAt, before, after, "FundsTransfer entity CreatedAt is incorrect")
	assert.WithinRange(t, ft.LastSeen, before, after, "FundsTransfer entity LastSeen is incorrect")

	id, err := strconv.ParseInt(ft.ID, 10, 64)
	assert.NoError(t, err, "FundsTransfer entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "FundsTransfer entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, ft.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the FundsTransfer")
	assert.NotNil(t, found, "Entity found by ID for the FundsTransfer should not be nil")
	assert.Equal(t, ft.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the FundsTransfer does not match")
	assert.Equal(t, ft.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the FundsTransfer does not match")

	ft2, ok := found.Asset.(*oamfin.FundsTransfer)
	assert.True(t, ok, "Asset found by ID is not of type *oamfin.FundsTransfer")
	assert.Equal(t, found.ID, ft.ID, "FundsTransfer found by Entity ID does not have matching IDs")
	assert.Equal(t, ft2.ID, unique_id, "FundsTransfer found by ID does not have a matching ID")
	assert.Equal(t, ft2.Amount, amount, "FundsTransfer found by ID does not have a matching Amount")
	assert.Equal(t, ft2.ReferenceNumber, refID, "FundsTransfer found by ID does not have a matching ReferenceID")
	assert.Equal(t, ft2.Currency, currency, "FundsTransfer found by ID does not have a matching Currency")
	assert.Equal(t, ft2.Method, method, "FundsTransfer found by ID does not have a matching Method")
	assert.Equal(t, ft2.ExchangeDate, date, "FundsTransfer found by ID does not have a matching Date")
	assert.Equal(t, ft2.ExchangeRate, rate, "FundsTransfer found by ID does not have a matching ExchangeRate")

	err = suite.db.DeleteEntity(ctx, ft.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the FundsTransfer")

	_, err = suite.db.FindEntityById(ctx, ft.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the FundsTransfer")
}

func (suite *PostgresFundsTransferTestSuite) TestFindEntitiesByContentForFundsTransfer() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	unique_id := "test unique ID"
	amount := 1987.65
	refID := "test reference ID"
	currency := "USD"
	method := "wire transfer"
	date := time.Now().Add(-72 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	rate := 1.0

	ft, err := suite.db.CreateAsset(ctx, &oamfin.FundsTransfer{
		ID:              unique_id,
		Amount:          amount,
		ReferenceNumber: refID,
		Currency:        currency,
		Method:          method,
		ExchangeDate:    date,
		ExchangeRate:    rate,
	})
	assert.NoError(t, err, "Failed to create asset for the FundsTransfer")
	assert.NotNil(t, ft, "Entity for the FundsTransfer should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindOneEntityByContent(ctx, oam.FundsTransfer, after, dbt.ContentFilters{
		"unique_id": unique_id,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	found, err := suite.db.FindOneEntityByContent(ctx, oam.FundsTransfer, before, dbt.ContentFilters{
		"unique_id": unique_id,
	})
	assert.NoError(t, err, "Failed to find entity by content for the FundsTransfer")
	assert.NotNil(t, found, "Entity found by content for the FundsTransfer should not be nil")

	ft2, ok := found.Asset.(*oamfin.FundsTransfer)
	assert.True(t, ok, "FundsTransfer found by content is not of type *oamfin.FundsTransfer")
	assert.Equal(t, found.ID, ft.ID, "FundsTransfer found by content does not have matching IDs")
	assert.Equal(t, ft2.Amount, amount, "FundsTransfer found by content does not have a matching Amount")
	assert.Equal(t, ft2.ReferenceNumber, refID, "FundsTransfer found by ID does not have a matching ReferenceNumber")
	assert.Equal(t, ft2.Currency, currency, "FundsTransfer found by ID does not have a matching Currency")
	assert.Equal(t, ft2.Method, method, "FundsTransfer found by ID does not have a matching Method")
	assert.Equal(t, ft2.ExchangeDate, date, "FundsTransfer found by ID does not have a matching ExchangeDate")
	assert.Equal(t, ft2.ExchangeRate, rate, "FundsTransfer found by ID does not have a matching ExchangeRate")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.FundsTransfer, before, dbt.ContentFilters{
		"unique_id": unique_id,
	})
	assert.NoError(t, err, "Failed to find entities by content for the FundsTransfer")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the FundsTransfer")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.FundsTransfer, before, dbt.ContentFilters{
		"amount": amount,
	})
	assert.NoError(t, err, "Failed to find entities by content for the FundsTransfer")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the FundsTransfer")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.FundsTransfer, before, dbt.ContentFilters{
		"reference_number": refID,
	})
	assert.NoError(t, err, "Failed to find entities by content for the FundsTransfer")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the FundsTransfer")
}
