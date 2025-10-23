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

// sqliteRepository is a repository implementation.
type sqliteRepository struct {
	db     *sql.DB
	stmts  *Statements
	dbtype string
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (*sqliteRepository, error) {
	db, stmts, err := sqliteDatabase(dsn, 1, 1)
	if err != nil {
		return nil, err
	}

	return &sqliteRepository{
		db:     db,
		stmts:  stmts,
		dbtype: dbtype,
	}, nil
}

// sqliteDatabase creates a new SQLite database connection using the provided data source name (dsn).
func sqliteDatabase(dsn string, conns, idles int) (*sql.DB, *Statements, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	if err := ApplyPragmas(ctx, db); err != nil {
		return nil, nil, err
	}

	stmts, err := SeedAndPrepareAll(ctx, db, SeedOptions{RefreshTemplates: true})
	if err != nil {
		return nil, nil, err
	}

	db.SetMaxOpenConns(conns)
	db.SetMaxIdleConns(idles)
	db.SetConnMaxLifetime(time.Hour)
	db.SetConnMaxIdleTime(10 * time.Minute)
	return db, stmts, nil
}

// Close implements the Repository interface.
func (sql *sqliteRepository) Close() error {
	if sql.stmts != nil {
		sql.stmts.Close()
	}
	if sql.db != nil {
		return sql.db.Close()
	}
	return errors.New("failed to obtain access to the database handle")
}

// GetDBType returns the type of the database.
func (sql *sqliteRepository) GetDBType() string {
	return sql.dbtype
}
