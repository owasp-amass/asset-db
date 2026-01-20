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
	oamfile "github.com/owasp-amass/open-asset-model/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresFileTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresFileTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresFileTestSuite))
}

func (suite *PostgresFileTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresFileTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresFileTestSuite) TestCreateAssetForFile() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	url := "https://www.owasp.org/contact.html"
	name := "contact.html"
	fileType := "text/html"
	fasset, err := suite.db.CreateAsset(ctx, &oamfile.File{
		URL:  url,
		Name: name,
		Type: fileType,
	})
	assert.NoError(t, err, "Failed to create asset for the File")
	assert.NotNil(t, fasset, "Entity for the File should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, fasset.CreatedAt, before, after, "File entity CreatedAt is incorrect")
	assert.WithinRange(t, fasset.LastSeen, before, after, "File entity LastSeen is incorrect")

	id, err := strconv.ParseInt(fasset.ID, 10, 64)
	assert.NoError(t, err, "File entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "File entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, fasset.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the File")
	assert.NotNil(t, found, "Entity found by ID for the File should not be nil")
	assert.Equal(t, fasset.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the File does not match")
	assert.Equal(t, fasset.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the File does not match")

	fasset2, ok := found.Asset.(*oamfile.File)
	assert.True(t, ok, "Asset found by ID is not of type *oamfile.File")
	assert.Equal(t, found.ID, fasset.ID, "File found by Entity ID does not have matching IDs")
	assert.Equal(t, fasset2.URL, url, "File found by ID does not have a matching URL")
	assert.Equal(t, fasset2.Name, name, "File found by ID does not have a matching Name")
	assert.Equal(t, fasset2.Type, fileType, "File found by ID does not have a matching Type")

	err = suite.db.DeleteEntity(ctx, fasset.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the File")

	_, err = suite.db.FindEntityById(ctx, fasset.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the File")
}

func (suite *PostgresFileTestSuite) TestFindEntitiesByContentForFile() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	url := "https://www.owasp.org/contact.html"
	name := "contact.html"
	fileType := "text/html"
	fasset, err := suite.db.CreateAsset(ctx, &oamfile.File{
		URL:  url,
		Name: name,
		Type: fileType,
	})
	assert.NoError(t, err, "Failed to create asset for the File")
	assert.NotNil(t, fasset, "Entity for the File should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindEntitiesByContent(ctx, oam.File, after, 1, dbt.ContentFilters{
		"url": url,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.File, before, 1, dbt.ContentFilters{
		"url": url,
	})
	assert.NoError(t, err, "Failed to find entity by content for the File")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the File should not be nil")

	fasset2, ok := found.Asset.(*oamfile.File)
	assert.True(t, ok, "File found by content is not of type *oamfile.File")
	assert.Equal(t, found.ID, fasset.ID, "File found by content does not have matching IDs")
	assert.Equal(t, fasset2.URL, url, "File found by ID does not have a matching URL")
	assert.Equal(t, fasset2.Name, name, "File found by ID does not have a matching Name")
	assert.Equal(t, fasset2.Type, fileType, "File found by ID does not have a matching Type")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.File, before, 0, dbt.ContentFilters{
		"name": name,
	})
	assert.NoError(t, err, "Failed to find entities by content for the File")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the File")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.File, before, 0, dbt.ContentFilters{
		"type": fileType,
	})
	assert.NoError(t, err, "Failed to find entities by content for the File")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the File")
}

func (suite *PostgresFileTestSuite) TestFindEntitiesByTypeForFile() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	atype := oam.File
	atypestr := "File"
	key1 := "https://owasp.org/fake1.html"
	ent, err := suite.db.CreateAsset(ctx, &oamfile.File{URL: key1})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := "https://owasp.org/fake2.html"
	ent, err = suite.db.CreateAsset(ctx, &oamfile.File{URL: key2})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "https://owasp.org/fake3.html"
	ent, err = suite.db.CreateAsset(ctx, &oamfile.File{URL: key3})
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
