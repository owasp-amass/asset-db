// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assetdb

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/config"
	neomigrations "github.com/owasp-amass/asset-db/migrations/neo4j"

	//pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	migrate "github.com/rubenv/sql-migrate"
	//"gorm.io/driver/postgres"
)

// New creates a new assetDB instance.
// It initializes the asset database with the specified database type and DSN.
func New(dbtype, dsn string) (repository.Repository, error) {
	if dbtype == sqlite3.SQLiteMemory {
		dsn = fmt.Sprintf("file:mem%d?mode=memory&cache=shared&_busy_timeout=15000&_foreign_keys=on&_journal_mode=WAL", rand.Intn(1000))
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
	switch dbtype {
	case sqlite3.SQLite:
		fallthrough
	case sqlite3.SQLiteMemory:
		if db, err := sql.Open("sqlite3", dsn); err == nil {
			return sqliteMigrate("sqlite3", db, sqlitemigrations.Migrations())
		}
	/*case sqlrepo.Postgres:
	return sqlMigrate("postgres", postgres.Open(dsn), pgmigrations.Migrations())*/
	case neo4j.Neo4j:
		return neoMigrate(dsn)
	}
	return nil
}

func sqliteMigrate(name string, db *sql.DB, fs embed.FS) error {
	defer func() { _ = db.Close() }()

	migsrc := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}

	_, err := migrate.Exec(db, name, migsrc, migrate.Up)
	return err
}

func neoMigrate(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return err
	}

	auth := neo4jdb.NoAuth()
	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
		auth = neo4jdb.BasicAuth(username, password, "")
	}
	dbname := strings.TrimPrefix(u.Path, "/")

	newdsn := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	driver, err := neo4jdb.NewDriverWithContext(newdsn, auth, func(cfg *config.Config) {
		cfg.MaxConnectionPoolSize = 20
		cfg.MaxConnectionLifetime = time.Hour
		cfg.ConnectionLivenessCheckTimeout = 10 * time.Minute
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := driver.VerifyConnectivity(ctx); err != nil {
		return err
	}
	defer func() { _ = driver.Close(context.Background()) }()

	return neomigrations.InitializeSchema(driver, dbname)
}
