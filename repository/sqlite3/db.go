// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
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
	fdsn += `&_time_format=sqlite&_pragma=journal_mode(WAL)&_pragma=temp_store(FILE)&_pragma=page_size(4096)&_pragma=cache_size(-64000)`

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
		_ = dbro.Close()
		_ = db.Close()
		return nil, err
	}
	return repo, repo.prepareWorkers()
}

func (r *SqliteRepository) migrate() error {
	if err := r.normalizeMigrationTimestamps(); err != nil {
		return err
	}
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

// Go's numeric-only zone name is not readable by the SQLite driver's time parser.
var numericZoneTimestamp = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?) ([+-][0-9]{4}) ([+-][0-9]{4})(?: m=[+-][0-9]+(?:\.[0-9]+)?)?$`)

func (r *SqliteRepository) normalizeMigrationTimestamps() error {
	// Reserve the writer before reading history so concurrent repairs cannot
	// try to upgrade an obsolete WAL read snapshot.
	ctx := context.Background()
	conn, err := r.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(ctx, "ROLLBACK") }()
	var exists int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='gorp_migrations'").Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		_, err := conn.ExecContext(ctx, "COMMIT")
		return err
	}
	rows, err := conn.QueryContext(ctx, "SELECT id, CAST(applied_at AS TEXT) FROM gorp_migrations")
	if err != nil {
		return err
	}
	type correction struct{ id, before, after string }
	var corrections []correction
	for rows.Next() {
		var id, stamp string
		if err := rows.Scan(&id, &stamp); err != nil {
			_ = rows.Close()
			return err
		}
		match := numericZoneTimestamp.FindStringSubmatch(stamp)
		if match == nil || match[2] != match[3] {
			continue
		}
		parsed, err := time.Parse("2006-01-02 15:04:05 -0700", strings.Join(match[1:3], " "))
		if err != nil {
			continue
		}
		corrections = append(corrections, correction{id, stamp, parsed.Format(time.RFC3339Nano)})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, c := range corrections {
		if _, err := conn.ExecContext(ctx, "UPDATE gorp_migrations SET applied_at=? WHERE id=? AND CAST(applied_at AS TEXT)=?", c.after, c.id, c.before); err != nil {
			return err
		}
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}
