// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlrepo

import (
	"errors"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	Postgres     string = "postgres"
	SQLite       string = "sqlite"
	SQLiteMemory string = "sqlite_memory"
)

// sqlRepository is a repository implementation using GORM as the underlying ORM.
type sqlRepository struct {
	db     *gorm.DB
	dbtype string
}

// New creates a new instance of the asset database repository.
func New(dbtype, dsn string) (*sqlRepository, error) {
	db, err := newDatabase(dbtype, dsn)
	if err != nil {
		return nil, err
	}

	return &sqlRepository{
		db:     db,
		dbtype: dbtype,
	}, nil
}

// newDatabase creates a new GORM database connection based on the provided database type and data source name (dsn).
func newDatabase(dbtype, dsn string) (*gorm.DB, error) {
	switch dbtype {
	case Postgres:
		return postgresDatabase(dsn)
	case SQLite:
		fallthrough
	case SQLiteMemory:
		return sqliteDatabase(dsn)
	}
	return nil, errors.New("unknown DB type")
}

// postgresDatabase creates a new PostgreSQL database connection using the provided data source name (dsn).
func postgresDatabase(dsn string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
}

// sqliteDatabase creates a new SQLite database connection using the provided data source name (dsn).
func sqliteDatabase(dsn string) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
}

// Close implements the Repository interface.
func (sql *sqlRepository) Close() error {
	if db, err := sql.db.DB(); err == nil {
		return db.Close()
	}
	return errors.New("failed to obtain access to the database handle")
}

// GetDBType returns the type of the database.
func (sql *sqlRepository) GetDBType() string {
	return string(sql.dbtype)
}