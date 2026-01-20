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
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresAutnumRecordTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresAutnumRecordTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresAutnumRecordTestSuite))
}

func (suite *PostgresAutnumRecordTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresAutnumRecordTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresAutnumRecordTestSuite) TestCreateAssetForAutnumRecord() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	number := 26808
	handle := "AS-TEST"
	recname := "Test Autnum Record"
	server := "whois.test.net"
	created := time.Now().Add(-24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	updated := time.Now().Add(-1 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	status := []string{"active"}

	ar, err := suite.db.CreateAsset(ctx, &oamreg.AutnumRecord{
		Number:      number,
		Handle:      handle,
		Name:        recname,
		WhoisServer: server,
		CreatedDate: created,
		UpdatedDate: updated,
		Status:      status,
	})
	assert.NoError(t, err, "Failed to create asset for the AutnumRecord")
	assert.NotNil(t, ar, "Entity for the AutnumRecord should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	assert.WithinRange(t, ar.CreatedAt, before, after, "AutnumRecord entity CreatedAt is incorrect")
	assert.WithinRange(t, ar.LastSeen, before, after, "AutnumRecord entity LastSeen is incorrect")

	id, err := strconv.ParseInt(ar.ID, 10, 64)
	assert.NoError(t, err, "AutnumRecord entity ID is not a valid integer")
	assert.Greater(t, id, int64(0), "AutnumRecord entity ID is not greater than zero")

	found, err := suite.db.FindEntityById(ctx, ar.ID)
	assert.NoError(t, err, "Failed to find entity by ID for the AutnumRecord")
	assert.NotNil(t, found, "Entity found by ID for the AutnumRecord should not be nil")
	assert.Equal(t, ar.CreatedAt, found.CreatedAt, "Entity CreatedAt found by ID for the AutnumRecord does not match")
	assert.Equal(t, ar.LastSeen, found.LastSeen, "Entity LastSeen found by ID for the AutnumRecord does not match")

	ar2, ok := found.Asset.(*oamreg.AutnumRecord)
	assert.True(t, ok, "AutnumRecord found by ID is not of type *oamreg.AutnumRecord")
	assert.Equal(t, found.ID, ar.ID, "AutnumRecord found by Entity ID does not have matching IDs")
	assert.Equal(t, ar2.Number, number, "AutnumRecord found by ID does not have matching number")
	assert.Equal(t, ar2.Handle, handle, "AutnumRecord found by ID does not have matching handle")
	assert.Equal(t, ar2.Name, recname, "AutnumRecord found by ID does not have matching name")
	assert.Equal(t, ar2.WhoisServer, server, "AutnumRecord found by ID does not have matching whois_server")
	assert.Equal(t, ar2.CreatedDate, created, "AutnumRecord found by ID does not have matching created_date")
	assert.Equal(t, ar2.UpdatedDate, updated, "AutnumRecord found by ID does not have matching updated")
	assert.Equal(t, ar2.Status, status, "AutnumRecord found by ID does not have matching status")

	err = suite.db.DeleteEntity(ctx, ar.ID)
	assert.NoError(t, err, "Failed to delete entity by ID for the AutnumRecord")

	_, err = suite.db.FindEntityById(ctx, ar.ID)
	assert.Error(t, err, "Expected error when finding deleted entity by ID for the AutnumRecord")
}

func (suite *PostgresAutnumRecordTestSuite) TestFindEntitiesByContentForAutnumRecord() {
	t := suite.T()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := time.Now()
	time.Sleep(100 * time.Millisecond)
	number := 26808
	handle := "AS-TEST"
	recname := "Test Autnum Record"
	server := "whois.test.net"
	created := time.Now().Add(-24 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	updated := time.Now().Add(-1 * time.Hour).In(time.UTC).Format("2006-01-02T15:04:05")
	status := []string{"active"}

	ar, err := suite.db.CreateAsset(ctx, &oamreg.AutnumRecord{
		Number:      number,
		Handle:      handle,
		Name:        recname,
		WhoisServer: server,
		CreatedDate: created,
		UpdatedDate: updated,
		Status:      status,
	})
	assert.NoError(t, err, "Failed to create asset for the AutnumRecord")
	assert.NotNil(t, ar, "Entity for the AutnumRecord should not be nil")
	time.Sleep(100 * time.Millisecond)
	after := time.Now()

	_, err = suite.db.FindEntitiesByContent(ctx, oam.AutnumRecord, after, 1, dbt.ContentFilters{
		"handle": handle,
	})
	assert.Error(t, err, "Expected error when finding entity with CreatedAt after its creation time")

	ents, err := suite.db.FindEntitiesByContent(ctx, oam.AutnumRecord, before, 1, dbt.ContentFilters{
		"handle": handle,
	})
	assert.NoError(t, err, "Failed to find entity by content for the AutnumRecord")
	found := ents[0]
	assert.NotNil(t, found, "Entity found by content for the AutnumRecord should not be nil")

	ar2, ok := found.Asset.(*oamreg.AutnumRecord)
	assert.True(t, ok, "AutnumRecord found by content is not of type *oamreg.AutnumRecord")
	assert.Equal(t, found.ID, ar.ID, "AutnumRecord found by content does not have matching IDs")
	assert.Equal(t, ar2.Number, number, "AutnumRecord found by ID does not have matching number")
	assert.Equal(t, ar2.Handle, handle, "AutnumRecord Handle found by content does not match")
	assert.Equal(t, ar2.Name, recname, "AutnumRecord Name found by content does not match")
	assert.Equal(t, ar2.WhoisServer, server, "AutnumRecord WhoisServer found by content does not match")
	assert.Equal(t, ar2.CreatedDate, created, "AutnumRecord CreatedDate found by content does not match")
	assert.Equal(t, ar2.UpdatedDate, updated, "AutnumRecord UpdatedDate found by content does not match")
	assert.Equal(t, ar2.Status, status, "AutnumRecord Status found by content does not match")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.AutnumRecord, before, 0, dbt.ContentFilters{
		"number": number,
	})
	assert.NoError(t, err, "Failed to find entities by content for the AutnumRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the AutnumRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.AutnumRecord, before, 0, dbt.ContentFilters{
		"handle": handle,
	})
	assert.NoError(t, err, "Failed to find entities by content for the AutnumRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the AutnumRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.AutnumRecord, time.Time{}, 0, dbt.ContentFilters{
		"name": recname,
	})
	assert.NoError(t, err, "Failed to find entities by content for the AutnumRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the AutnumRecord")

	ents, err = suite.db.FindEntitiesByContent(ctx, oam.AutnumRecord, time.Time{}, 0, dbt.ContentFilters{
		"whois_server": server,
	})
	assert.NoError(t, err, "Failed to find entities by content for the AutnumRecord")
	assert.Len(t, ents, 1, "Expected to find exactly one entity by content for the AutnumRecord")
}

func (suite *PostgresAutnumRecordTestSuite) TestFindEntitiesByTypeForAutnumRecord() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since1 := time.Now()
	created := since1.UTC().Format("2006-01-02T15:04:05")
	updated := created
	time.Sleep(100 * time.Millisecond)

	key1 := "Fake1"
	atype := oam.AutnumRecord
	atypestr := "AutnumRecord"
	ent, err := suite.db.CreateAsset(ctx, &oamreg.AutnumRecord{
		Number:      12345,
		Handle:      key1,
		Name:        "fake name 1",
		CreatedDate: created,
		UpdatedDate: updated,
	})
	assert.NoError(t, err, "Failed to create asset for the first %s", atypestr)
	assert.NotNil(t, ent, "Entity for the first %s should not be nil", atypestr)

	time.Sleep(100 * time.Millisecond)
	after1 := time.Now()
	time.Sleep(500 * time.Millisecond)
	since23 := time.Now()
	time.Sleep(100 * time.Millisecond)

	key2 := "Fake2"
	ent, err = suite.db.CreateAsset(ctx, &oamreg.AutnumRecord{
		Number:      67890,
		Handle:      key2,
		Name:        "fake name 2",
		CreatedDate: created,
		UpdatedDate: updated,
	})
	assert.NoError(t, err, "Failed to create asset for the second %s", atypestr)
	assert.NotNil(t, ent, "Entity for the second %s should not be nil", atypestr)

	key3 := "Fake3"
	ent, err = suite.db.CreateAsset(ctx, &oamreg.AutnumRecord{
		Number:      123890,
		Handle:      key3,
		Name:        "fake name 3",
		CreatedDate: created,
		UpdatedDate: updated,
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
