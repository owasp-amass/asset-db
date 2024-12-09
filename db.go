// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assetdb

import (
	"embed"
	"fmt"
	"math/rand"

	"github.com/glebarez/sqlite"
	pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlrepo"
	migrate "github.com/rubenv/sql-migrate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// New creates a new assetDB instance.
// It initializes the asset database with the specified database type and DSN.
func New(dbtype, dsn string) (repository.Repository, error) {
	if dbtype == sqlrepo.SQLiteMemory {
		dsn = fmt.Sprintf("file:mem%d?mode=memory&cache=shared", rand.Intn(1000))
	}

	db, err := repository.New(dbtype, dsn)
	if err != nil {
		return nil, err
	}
	if err := migrateDatabase(dbtype, dsn); err != nil {
		return nil, err
	}
	return db, nil
}

func migrateDatabase(dbtype, dsn string) error {
	var name string
	var fs embed.FS
	var database gorm.Dialector

	switch dbtype {
	case sqlrepo.SQLite:
		fallthrough
	case sqlrepo.SQLiteMemory:
		name = "sqlite3"
		fs = sqlitemigrations.Migrations()
		database = sqlite.Open(dsn)
	case sqlrepo.Postgres:
		name = "postgres"
		fs = pgmigrations.Migrations()
		database = postgres.Open(dsn)
	}

	sql, err := gorm.Open(database, &gorm.Config{})
	if err != nil {
		return err
	}

	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}

	sqlDb, err := sql.DB()
	if err != nil {
		return err
	}
	defer sqlDb.Close()

	_, err = migrate.Exec(sqlDb, name, migrationsSource, migrate.Up)
	if err != nil {
		return err
	}
	return nil
}
