// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

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
	pool   *Worker
	dsn    string
	cfg    WorkerConfig
	dbtype string
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (*PostgresRepository, error) {
	if dbtype != Postgres {
		return nil, fmt.Errorf("unsupported database type: %s", dbtype)
	}

	repo, err := postgresDatabase(dsn, WorkerConfig{
		PoolMinConns:      2,
		PoolMaxConns:      int32(numberOfWorkers),
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: 1 * time.Minute,
		StatementTimeout:  60 * time.Second,
		ApplicationName:   "asset-db",
	})
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// postgresDatabase creates a new PostgreSQL database connection using the provided data source name (dsn).
func postgresDatabase(dsn string, cfg WorkerConfig) (*PostgresRepository, error) {
	dsn = dsn + "?sslmode=disable&statement_cache_capacity=256&timezone=UTC&connect_timeout=5"
	dsn = dsn + "&application_name=asset-db&statement_timeout=60000&lock_timeout=5000"

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		pctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

		err = db.PingContext(pctx)
		cancel()
		if err == nil {
			break
		}

		if time.Now().After(deadline) {
			_ = db.Close()
			return nil, err
		}
		time.Sleep(200 * time.Millisecond)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	return &PostgresRepository{
		DB:     db,
		dsn:    dsn,
		cfg:    withDefaults(cfg),
		dbtype: Postgres,
	}, nil
}

func (pr *PostgresRepository) Prepare(ctx context.Context) error {
	w, err := NewWorker(ctx, pr.dsn, pr.cfg)
	if err != nil {
		return err
	}

	pr.pool = w
	return nil
}

// Close implements the Repository interface.
func (pr *PostgresRepository) Close() error {
	if pr.pool != nil {
		pr.pool.Shutdown(context.TODO())
	}
	if pr.DB != nil {
		return pr.DB.Close()
	}
	return errors.New("failed to obtain access to the database handle")
}

// GetDBType returns the type of the database.
func (sql *PostgresRepository) GetDBType() string {
	return sql.dbtype
}
