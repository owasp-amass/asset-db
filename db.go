// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assetdb

import (
	"context"
	"embed"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/config"
	neomigrations "github.com/owasp-amass/asset-db/migrations/neo4j"
	pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/neo4j"
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
	switch dbtype {
	case sqlrepo.SQLite:
		fallthrough
	case sqlrepo.SQLiteMemory:
		return sqlMigrate("sqlite3", sqlite.Open(dsn), sqlitemigrations.Migrations())
	case sqlrepo.Postgres:
		return sqlMigrate("postgres", postgres.Open(dsn), pgmigrations.Migrations())
	case neo4j.Neo4j:
		return neoMigrate(dsn)
	}
	return nil
}

func sqlMigrate(name string, database gorm.Dialector, fs embed.FS) error {
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
	defer func() { _ = sqlDb.Close() }()

	_, err = migrate.Exec(sqlDb, name, migrationsSource, migrate.Up)
	if err != nil {
		return err
	}
	return nil
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
