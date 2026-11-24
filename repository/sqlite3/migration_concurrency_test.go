// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
)

func TestSQLiteConcurrentMigrationTimestampRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.db")
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open(SQLite, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close setup connection: %v", err)
		}
	})
	if _, err = db.Exec("CREATE TABLE gorp_migrations (id TEXT PRIMARY KEY, applied_at DATETIME)"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if _, err = db.Exec("INSERT INTO gorp_migrations VALUES (?, ?)", i, "2026-11-13 17:51:45.116244512 +0530 +0530 m=+12.169086956"); err != nil {
			t.Fatal(err)
		}
	}
	// Open each connection before the barrier: lazy opens can serialize the
	// first repair and hide conflicting read snapshots.
	start := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		rdb, e := sql.Open(SQLite, dsn)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if err := rdb.Close(); err != nil {
				t.Errorf("close repair connection: %v", err)
			}
		})
		rdb.SetMaxOpenConns(1)
		if e = rdb.Ping(); e != nil {
			t.Fatal(e)
		}
		r := &SqliteRepository{DB: rdb}
		wg.Add(1)
		go func() { defer wg.Done(); <-start; errs <- r.normalizeMigrationTimestamps() }()
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Error(e)
		}
	}

	var remaining int
	if err := db.QueryRow("SELECT count(*) FROM gorp_migrations WHERE CAST(applied_at AS TEXT) NOT LIKE '%T%'").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("%d timestamps were not repaired", remaining)
	}
}
