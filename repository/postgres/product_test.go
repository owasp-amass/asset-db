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

type PostgresProductTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresProductTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresProductTestSuite))
}

func (suite *PostgresProductTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresProductTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresProductTestSuite) TestCreateAssetForProduct() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uniqueID := "fake unique id"
	name := "Fake Product"
	ptype := "Fake Product Type"
	cat := "Fake Category"
	desc := "This is a fake product used for testing purposes."
	country := "US"

	product, err := suite.db.CreateAsset(ctx, &oamplat.Product{
		ID:              uniqueID,
		Name:            name,
		Type:            ptype,
		Category:        cat,
		Description:     desc,
		CountryOfOrigin: country,
	})
	assert.NoError(t, err, "Failed to create asset for the Product")
	assert.NotNil(t, product, "Entity for the Product should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, product.CreatedAt, before, after, "Product entity CreatedAt is incorrect")
	assert.WithinRange(t, product.LastSeen, before, after, "Product entity LastSeen is incorrect")

	id, err := strconv.ParseInt(product.ID, 10, 64)
	assert.NoError(t, err, "Product entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "Product entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, product.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the Product")
	assert.NotNil(t, found, "Entity found by ID for the Product should not be nil")
	assert.Equal(t, product.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the Product does not match")
	assert.Equal(t, product.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the Product does not match")

	product2, ok := found.Asset.(*oamplat.Product)
	assert.True(t, ok, "Product found by ID is not of type *oamplat.Product")
	assert.Equal(t, found.ID, product.ID, "Product found by Entity ID does not have matching IDs")
	assert.Equal(t, product2.ID, uniqueID, "Product found by ID does not have matching UniqueID")
	assert.Equal(t, product2.Name, name, "Product found by ID does not have matching Name")
	assert.Equal(t, product2.Type, ptype, "Product found by ID does not have matching Type")
	assert.Equal(t, product2.Category, cat, "Product found by ID does not have matching Category")
	assert.Equal(t, product2.Description, desc, "Product found by ID does not have matching Description")
	assert.Equal(t, product2.CountryOfOrigin, country, "Product found by ID does not have matching CountryOfOrigin")

	err = suite.db.DeleteEntity(ctx, product.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the Product")

	_, err = suite.db.FindEntityById(ctx, product.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the Product")
}

func (suite *PostgresProductTestSuite) TestFindEntitiesByContentForProduct() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	uniqueID := "fake unique id"
	name := "Fake Product"
	ptype := "Fake Product Type"
	cat := "Fake Category"
	desc := "This is a fake product used for testing purposes."
	country := "US"

	product, err := suite.db.CreateAsset(ctx, &oamplat.Product{
		ID:              uniqueID,
		Name:            name,
		Type:            ptype,
		Category:        cat,
		Description:     desc,
		CountryOfOrigin: country,
	})
	assert.NoError(t, err, "Failed to create asset for the Product")
	assert.NotNil(t, product, "Entity for the Product should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindEntitiesByContent(ctx, oam.Product, after, 1, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.Product, before, 1, dbt.ContentFilters{
		"unique_id": uniqueID,
	})
	assert.NoError(t, err, "Failed to find entity by content for the Product")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the Product should not be nil")

	product2, ok := found.Asset.(*oamplat.Product)
	assert.True(t, ok, "Product found by content is not of type *oamplat.Product")
	assert.Equal(t, found.ID, product.ID, "Product found by content does not have matching IDs")
	assert.Equal(t, product2.ID, uniqueID, "Product found by content does not have matching unique ID")
	assert.Equal(t, product2.Name, name, "Product found by content does not have matching name")
	assert.Equal(t, product2.Type, ptype, "Product found by content does not have matching type")
	assert.Equal(t, product2.Category, cat, "Product found by content does not have matching category")
	assert.Equal(t, product2.Description, desc, "Product found by content does not have matching description")
	assert.Equal(t, product2.CountryOfOrigin, country, "Product found by content does not have matching country of origin")

	for k, v := range map[string]string{
		"unique_id":    uniqueID,
		"product_name": name,
		"product_type": ptype,
	} {
		ents, err := suite.db.FindEntitiesByContent(ctx, oam.Product, before, 0, dbt.ContentFilters{k: v})
		assert.NoError(t, err, "Failed to find entities by content for the Product")
		assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the Product")
	}
}

func (suite *PostgresProductTestSuite) TestFindEntitiesByTypeForProduct() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key1 := "Fake1"
	atype := oam.Product
	atypestr := "Product"
	ent, err := suite.db.CreateAsset(ctx, &oamplat.Product{
		ID:   key1,
		Name: "fake name 1",
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
	ent, err = suite.db.CreateAsset(ctx, &oamplat.Product{
		ID:   key2,
		Name: "fake name 2",
		Type: "fake type 2",
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "Fake3"
	ent, err = suite.db.CreateAsset(ctx, &oamplat.Product{
		ID:   key3,
		Name: "fake name 3",
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
