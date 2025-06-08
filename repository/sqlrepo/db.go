// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlrepo

import (
	"errors"
	"time"

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
		return sqliteDatabase(dsn, 1, 1)
	case SQLiteMemory:
		return sqliteDatabase(dsn, 1, 1)
	}
	return nil, errors.New("unknown DB type")
}

// postgresDatabase creates a new PostgreSQL database connection using the provided data source name (dsn).
func postgresDatabase(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(2)
	sqlDB.SetMaxOpenConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)
	return db, nil
}

// sqliteDatabase creates a new SQLite database connection using the provided data source name (dsn).
func sqliteDatabase(dsn string, conns, idles int) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(conns)
	sqlDB.SetMaxIdleConns(idles)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)
	return db, nil
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
	return sql.dbtype
}
