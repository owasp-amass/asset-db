// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	SQLite       string = "sqlite"
	SQLiteMemory string = "sqlite_memory"
)

// SqliteRepository is a repository implementation.
type SqliteRepository struct {
	DB            *sql.DB
	queries       *Queries
	fqdnStmts     *fqdnStatements
	netblockStmts *netblockStatements
	dbtype        string
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (*SqliteRepository, error) {
	repo, err := sqliteDatabase(dsn, 1, 1)
	if err != nil {
		return nil, err
	}

	repo.dbtype = dbtype
	return repo, nil
}

func (sql *SqliteRepository) Prepare(ctx context.Context) error {
	err := ApplyPragmas(context.Background(), sql.DB)
	if err != nil {
		return err
	}

	if err := sql.prepareNetblockStatements(ctx); err != nil {
		return err
	}

	queries, err := NewQueries(sql.DB)
	if err != nil {
		return err
	}
	sql.queries = queries
	return nil
}

// sqliteDatabase creates a new SQLite database connection using the provided data source name (dsn).
func sqliteDatabase(dsn string, conns, idles int) (*SqliteRepository, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(conns)
	db.SetMaxIdleConns(idles)
	db.SetConnMaxLifetime(time.Hour)
	db.SetConnMaxIdleTime(10 * time.Minute)
	return &SqliteRepository{DB: db}, nil
}

// Close implements the Repository interface.
func (sql *SqliteRepository) Close() error {
	if sql.queries != nil {
		_ = sql.queries.Close()
	}

	if sql.netblockStmts != nil {
		if err := sql.closeNetblockStatements(); err != nil {
			return err
		}
	}

	if sql.DB != nil {
		return sql.DB.Close()
	}
	return errors.New("failed to obtain access to the database handle")
}

// GetDBType returns the type of the database.
func (sql *SqliteRepository) GetDBType() string {
	return sql.dbtype
}
