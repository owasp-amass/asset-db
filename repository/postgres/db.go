// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Normalized Property Graph (NPG) implemented on PostgreSQL

const (
	Postgres        string = "postgres"
	numberOfWorkers int    = 8
)

// PostgresRepository is a repository implementation.
type PostgresRepository struct {
	DB     *sql.DB
	rodb   *sql.DB
	ww     *writeWorker
	rpool  *readerWorkerPool
	dbtype string
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (*PostgresRepository, error) {
	if dbtype != Postgres {
		return nil, fmt.Errorf("unsupported database type: %s", dbtype)
	}

	repo, err := postgresDatabase(dsn)
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// postgresDatabase creates a new PostgreSQL database connection using the provided data source name (dsn).
func postgresDatabase(dsn string) (*PostgresRepository, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(numberOfWorkers)
	db.SetMaxIdleConns(numberOfWorkers / 2)
	db.SetConnMaxLifetime(10 * time.Minute)
	db.SetConnMaxIdleTime(time.Minute)

	return &PostgresRepository{
		DB:     db,
		dbtype: Postgres,
	}, nil
}

func (sql *PostgresRepository) Prepare(ctx context.Context) error {
	wworker, err := newWriteWorker(sql.DB, 20, 500*time.Microsecond)
	if err != nil {
		return err
	}
	sql.ww = wworker

	rpool, err := newReaderWorkerPool(sql.rodb, numberOfWorkers)
	if err != nil {
		return err
	}
	sql.rpool = rpool
	return nil
}

// Close implements the Repository interface.
func (sql *PostgresRepository) Close() error {
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

// GetDBType returns the type of the database.
func (sql *PostgresRepository) GetDBType() string {
	return sql.dbtype
}
