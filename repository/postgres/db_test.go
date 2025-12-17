// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"embed"
	"time"

	postgresmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	migrate "github.com/rubenv/sql-migrate"
)

func setupTestDB(dbtype, dsn string) (*PostgresRepository, error) {
	db, err := New(dbtype, dsn)
	if err != nil {
		return nil, err
	}

	if err := postgresMigrate(db, postgresmigrations.Migrations()); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.Prepare(ctx); err != nil {
		return nil, err
	}
	return db, nil
}

func postgresMigrate(repo *PostgresRepository, fs embed.FS) error {
	migsrc := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}

	_, err := migrate.Exec(repo.DB, "postgres", migsrc, migrate.Up)
	return err
}
