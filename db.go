// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assetdb

import (
	"context"
	"embed"
	"fmt"
	"time"

	neomigrations "github.com/owasp-amass/asset-db/migrations/neo4j"
	pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	migrate "github.com/rubenv/sql-migrate"
)

// New creates a new assetDB instance.
// It initializes the asset database with the specified database type and DSN.
func New(dbtype, dsn string) (repository.Repository, error) {
	db, err := repository.New(dbtype, dsn)
	if err != nil {
		return nil, err
	}

	if err := migrateDatabase(dbtype, db); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.Prepare(ctx); err != nil {
		return nil, err
	}
	return db, nil
}

func migrateDatabase(dbtype string, repo repository.Repository) error {
	switch dbtype {
	case sqlite3.SQLite:
		fallthrough
	case sqlite3.SQLiteMemory:
		return sqliteMigrate(repo, sqlitemigrations.Migrations())
	case postgres.Postgres:
		return postgresMigrate(repo, pgmigrations.Migrations())
	case neo4j.Neo4j:
		return neoMigrate(repo)
	}
	return nil
}

func sqliteMigrate(repo repository.Repository, fs embed.FS) error {
	migsrc := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}

	r, ok := repo.(*sqlite3.SqliteRepository)
	if !ok {
		return fmt.Errorf("failed to cast repository to sqliteRepository")
	}
	db := r.DB

	_, err := migrate.Exec(db, "sqlite3", migsrc, migrate.Up)
	return err
}

func postgresMigrate(repo repository.Repository, fs embed.FS) error {
	migsrc := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}

	r, ok := repo.(*postgres.PostgresRepository)
	if !ok {
		return fmt.Errorf("failed to cast repository to postgresRepository")
	}
	db := r.DB

	_, err := migrate.Exec(db, "postgres", migsrc, migrate.Up)
	return err
}

func neoMigrate(repo repository.Repository) error {
	r, ok := repo.(*neo4j.NeoRepository)
	if !ok {
		return fmt.Errorf("failed to cast repository to neoRepository")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := r.DB.VerifyConnectivity(ctx); err != nil {
		return err
	}

	return neomigrations.InitializeSchema(r.DB, "neo4j")
}
