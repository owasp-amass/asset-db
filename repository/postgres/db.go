// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
	postgresmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	migrate "github.com/rubenv/sql-migrate"
)

// Normalized Property Graph (NPG) implemented on PostgreSQL

const (
	Postgres      string = "postgres"
	numberOfConns int    = 3
)

// PostgresRepository is a repository implementation.
type PostgresRepository struct {
	DB     *sql.DB
	dsn    string
	rpool  *Worker
	rcfg   WorkerConfig
	wpool  *Worker
	wcfg   WorkerConfig
	dbtype string
	cancel context.CancelFunc
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (*PostgresRepository, error) {
	if dbtype != Postgres {
		return nil, fmt.Errorf("unsupported database type: %s", dbtype)
	}

	rcfg := WorkerConfig{
		PoolMinConns:      1,
		PoolMaxConns:      int32(numberOfConns),
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: 1 * time.Minute,
		StatementTimeout:  120 * time.Second,
		ApplicationName:   "asset-db reader",
	}

	wcfg := WorkerConfig{
		TxMode:            true,
		PoolMinConns:      1,
		PoolMaxConns:      1,
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: 1 * time.Minute,
		StatementTimeout:  120 * time.Second,
		ApplicationName:   "asset-db writer",
	}

	repo, err := postgresDatabase(dsn, rcfg, wcfg)
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// postgresDatabase creates a new PostgreSQL database connection using the provided data source name (dsn).
func postgresDatabase(dsn string, rcfg, wcfg WorkerConfig) (*PostgresRepository, error) {
	dsn = dsn + "?sslmode=disable&statement_cache_capacity=256&timezone=UTC&connect_timeout=5"
	dsn = dsn + "&application_name=asset-db&statement_timeout=60000&lock_timeout=5000"

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		pctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

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
	repo := &PostgresRepository{
		DB:     db,
		dsn:    dsn,
		rcfg:   withDefaults(rcfg),
		wcfg:   withDefaults(wcfg),
		dbtype: Postgres,
	}

	if err := repo.migrate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	r, err := NewWorker(ctx, repo.dsn, repo.rcfg)
	if err != nil {
		cancel()
		return nil, err
	}
	repo.rpool = r

	w, err := NewWorker(ctx, repo.dsn, repo.wcfg)
	if err != nil {
		cancel()
		return nil, err
	}

	repo.wpool = w
	repo.cancel = cancel
	return repo, nil
}

func (pr *PostgresRepository) migrate() error {
	fs := postgresmigrations.Migrations()
	migsrc := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}

	_, err := migrate.Exec(pr.DB, "postgres", migsrc, migrate.Up)
	return err
}

// Close implements the Repository interface.
func (pr *PostgresRepository) Close() error {
	if pr.cancel != nil {
		pr.cancel()
	}
	if pr.rpool != nil {
		_ = pr.rpool.Shutdown(context.TODO())
	}
	if pr.wpool != nil {
		_ = pr.wpool.Shutdown(context.TODO())
	}
	if pr.DB != nil {
		return pr.DB.Close()
	}
	return errors.New("failed to obtain access to the database handle")
}

// Type implements the Repository interface.
func (pr *PostgresRepository) Type() string {
	return pr.dbtype
}
