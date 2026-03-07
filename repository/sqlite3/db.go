// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	migrate "github.com/rubenv/sql-migrate"
	_ "modernc.org/sqlite"
)

// Normalized Property Graph (NPG) implemented on SQLite

const (
	SQLite                string = "sqlite"
	numberOfReaderWorkers int    = 8
)

// SqliteRepository is a repository implementation.
type SqliteRepository struct {
	DB     *sql.DB
	rodb   *sql.DB
	ww     *writeWorker
	rpool  *readerWorkerPool
	dbtype string
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (*SqliteRepository, error) {
	var err error
	var repo *SqliteRepository

	switch dbtype {
	case SQLite:
		repo, err = sqliteDatabase(dsn)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbtype)
	}
	if err != nil {
		return nil, err
	}

	return repo, nil
}

// sqliteDatabase creates a new SQLite database connection using the provided data source name (dsn).
func sqliteDatabase(dsn string) (*SqliteRepository, error) {
	fdsn := dsn + `?_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)`
	fdsn += `&_pragma=journal_mode(WAL)&_pragma=temp_store(FILE)&_pragma=page_size(4096)&_pragma=cache_size(-64000)`

	db, err := sql.Open(SQLite, fdsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	dbro, err := sql.Open(SQLite, fdsn)
	if err != nil {
		return nil, err
	}

	dbro.SetMaxOpenConns(numberOfReaderWorkers)
	dbro.SetMaxIdleConns(numberOfReaderWorkers)
	dbro.SetConnMaxLifetime(0)

	repo := &SqliteRepository{
		DB:     db,
		rodb:   dbro,
		dbtype: SQLite,
	}

	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, repo.prepareWorkers()
}

func (r *SqliteRepository) migrate() error {
	fs := sqlitemigrations.Migrations()
	migsrc := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}

	_, err := migrate.Exec(r.DB, "sqlite3", migsrc, migrate.Up)
	return err
}

func (r *SqliteRepository) prepareWorkers() error {
	wworker, err := newWriteWorker(r.DB, 20, 500*time.Microsecond)
	if err != nil {
		return err
	}
	r.ww = wworker

	rpool, err := newReaderWorkerPool(r.rodb, numberOfReaderWorkers)
	if err != nil {
		return err
	}
	r.rpool = rpool
	return nil
}

// Close implements the Repository interface.
func (r *SqliteRepository) Close() error {
	if r.rpool != nil {
		r.rpool.Close()
	}
	if r.ww != nil {
		r.ww.Close()
	}
	if r.rodb != nil {
		_ = r.rodb.Close()
	}
	if r.DB != nil {
		return r.DB.Close()
	}
	return errors.New("failed to obtain access to the database handle")
}

// Type implements the Repository interface.
func (r *SqliteRepository) Type() string {
	return r.dbtype
}
