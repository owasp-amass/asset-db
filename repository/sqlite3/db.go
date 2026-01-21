// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Normalized Property Graph (NPG) implemented on SQLite

const (
	SQLite                string = "sqlite"
	SQLiteMemory          string = "sqlite_memory"
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
	case SQLiteMemory:
		repo, err = sqliteMemoryDatabase()
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
	wdsn := dsn + "?_synchronous=NORMAL&_busy_timeout=5000&_foreign_keys=on&_journal_mode=WAL"
	db, err := sql.Open("sqlite3", wdsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _ = db.ExecContext(ctx, `PRAGMA temp_store = FILE`)
	_, _ = db.ExecContext(ctx, `PRAGMA mmap_size = 0`) // disable memory-mapped I/O
	_, _ = db.ExecContext(ctx, `PRAGMA page_size = 4096`)
	_, _ = db.ExecContext(ctx, `PRAGMA cache_size = -500000`) // set cache size to 500 MiB (in KiB)

	rdsn := dsn + "?mode=ro&_busy_timeout=5000&_foreign_keys=on&_journal_mode=WAL"
	dbro, err := sql.Open("sqlite3", rdsn)
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
	return repo, repo.prepareWorkers()
}

// sqliteMemoryDatabase creates a new in-memory SQLite database connection.
func sqliteMemoryDatabase() (*SqliteRepository, error) {
	name := fmt.Sprintf("file:amassmem%d", rand.Intn(1000))
	dsn := name + `?mode=memory&cache=shared&_foreign_keys=on&_busy_timeout=5000&_synchronous=OFF&_journal_mode=MEMORY&_temp_store=MEMORY`

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _ = db.ExecContext(ctx, `PRAGMA page_size = 4096`)

	dbro, err := sql.Open("sqlite3", name+`?mode=memory&cache=shared&immutable=1`)
	if err != nil {
		return nil, err
	}

	dbro.SetMaxOpenConns(numberOfReaderWorkers)
	dbro.SetMaxIdleConns(numberOfReaderWorkers)
	dbro.SetConnMaxLifetime(0)

	repo := &SqliteRepository{
		DB:     db,
		rodb:   dbro,
		dbtype: SQLiteMemory,
	}
	return repo, repo.prepareWorkers()
}

func (sql *SqliteRepository) prepareWorkers() error {
	wworker, err := newWriteWorker(sql.DB, 20, 500*time.Microsecond)
	if err != nil {
		return err
	}
	sql.ww = wworker

	rpool, err := newReaderWorkerPool(sql.rodb, numberOfReaderWorkers)
	if err != nil {
		return err
	}
	sql.rpool = rpool
	return nil
}

// Close implements the Repository interface.
func (sql *SqliteRepository) Close() error {
	if sql.rpool != nil {
		sql.rpool.Close()
	}
	if sql.ww != nil {
		sql.ww.Close()
	}
	if sql.DB != nil {
		return sql.DB.Close()
	}
	return errors.New("failed to obtain access to the database handle")
}

// Type implements the Repository interface.
func (sql *SqliteRepository) Type() string {
	return sql.dbtype
}
