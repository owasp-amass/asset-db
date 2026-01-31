// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"database/sql"
	"fmt"
	"os"

	migrate "github.com/rubenv/sql-migrate"
	_ "modernc.org/sqlite"
)

func ExampleMigrations() {
	dsn := "test.db"
	if v, ok := os.LookupEnv("SQLITE3_DB"); ok {
		dsn = v
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		panic(err)
	}

	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: Migrations(),
		Root:       "/",
	}

	_, err = migrate.Exec(db, "sqlite3", migrationsSource, migrate.Up)
	if err != nil {
		panic(err)
	}

	tables := []string{"entities", "edges", "tags"}
	for range tables {
		fmt.Println(true)
	}

	err = os.Remove(dsn)
	if err != nil {
		panic(err)
	}

	// Output:
	// true
	// true
	// true
}
