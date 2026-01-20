// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/repository/postgres/testhelpers"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PostgresTagTestSuite struct {
	suite.Suite
	container *testhelpers.PostgresContainer
	db        *PostgresRepository
}

func TestPostgresTagTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresTagTestSuite))
}

func (suite *PostgresTagTestSuite) SetupSuite() {
	var err error
	suite.container, suite.db, err = setupContainerAndPostgresRepo()
	if err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresTagTestSuite) TearDownSuite() {
	if err := suite.container.Terminate(context.Background()); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func (suite *PostgresTagTestSuite) TestUpsertAndDeleteTag() {
	t := suite.T()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tag, err := suite.db.upsertTag(ctx, string(oam.SimpleProperty), "last_monitored", "fake date", "{}")
	assert.NoError(t, err, "Failed to create tag")
	assert.Greater(t, tag, int64(0), "Tag ID is not greater than zero")

	err = suite.db.deleteTagByID(ctx, tag, true)
	assert.NoError(t, err, "Failed to delete tag")
}
