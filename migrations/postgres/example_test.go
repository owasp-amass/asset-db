//go:build integration

// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"fmt"
	"log"
	"os"

	migrate "github.com/rubenv/sql-migrate"
	pg "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ExampleMigrations() {
	user := "postgres"
	if u, ok := os.LookupEnv("POSTGRES_USER"); ok {
		user = u
	}

	password := "postgres"
	if p, ok := os.LookupEnv("POSTGRES_PASSWORD"); ok {
		password = p
	}

	dbname := "postgres"
	if db, ok := os.LookupEnv("POSTGRES_DB"); ok {
		dbname = db
	}

	log.Printf("DSN: %s", fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s", user, password, dbname))

	dsn := fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s", user, password, dbname)
	db, err := gorm.Open(pg.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	sqlDb, _ := db.DB()

	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: Migrations(),
		Root:       "/",
	}

	_, err = migrate.Exec(sqlDb, "postgres", migrationsSource, migrate.Up)
	if err != nil {
		panic(err)
	}

	tables := []string{"entities", "entity_tags", "edges", "edge_tags"}
	for _, table := range tables {
		fmt.Println(db.Migrator().HasTable(table))
	}

	// Output:
	// true
	// true
	// true
	// true
}
