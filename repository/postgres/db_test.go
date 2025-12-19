// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"embed"
	"log"
	"testing"
	"time"

	postgresmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	"github.com/owasp-amass/asset-db/repository/postgres/testhelpers"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/stretchr/testify/suite"
)

type PostgresRepoTestSuite struct {
	suite.Suite
	pgContainer *testhelpers.PostgresContainer
	db          *PostgresRepository
	ctx         context.Context
}

func TestPostgresRepoTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresRepoTestSuite))
}

func (suite *PostgresRepoTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(suite.ctx)
	if err != nil {
		log.Fatal(err)
	}

	suite.pgContainer = pgContainer
	repository, err := New("postgres", suite.pgContainer.ConnectionString)
	if err != nil {
		log.Fatal(err)
	}

	suite.db = repository
	if err := postgresMigrate(suite.db, postgresmigrations.Migrations()); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := suite.db.Prepare(ctx); err != nil {
		log.Fatal(err)
	}
}

func (suite *PostgresRepoTestSuite) TearDownSuite() {
	if err := suite.pgContainer.Terminate(suite.ctx); err != nil {
		log.Fatalf("error terminating postgres container: %s", err)
	}
}

func postgresMigrate(repo *PostgresRepository, fs embed.FS) error {
	migsrc := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}

	_, err := migrate.Exec(repo.DB, "postgres", migsrc, migrate.Up)
	return err
}
