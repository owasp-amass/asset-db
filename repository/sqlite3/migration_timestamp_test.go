// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSQLiteNumericTimezoneReopen(t *testing.T) {
	previous := time.Local
	time.Local = time.FixedZone("", 19800)
	t.Cleanup(func() { time.Local = previous })
	path := filepath.Join(t.TempDir(), "asset.db")
	for i := 0; i < 2; i++ {
		repo, err := New(SQLite, path)
		if err != nil {
			t.Fatalf("open %d: %v", i+1, err)
		}
		var stamp string
		if err := repo.ww.conn.QueryRowContext(context.Background(), "SELECT CAST(applied_at AS TEXT) FROM gorp_migrations LIMIT 1").Scan(&stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", stamp); err != nil {
			t.Errorf("new timestamp is not SQLite-compatible: %q: %v", stamp, err)
		}
		if err := repo.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSQLiteLegacyMigrationTimestampReopen(t *testing.T) {
	for _, stamp := range []string{
		"2026-11-13 17:51:45.116244512 +0530 +0530 m=+12.169086956",
		"2026-11-13 17:51:45.116244512 -0430 -0430 m=+0.123",
		"2026-11-13 17:51:45 +0530 +0530",
	} {
		t.Run(stamp, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "asset.db")
			repo, err := New(SQLite, path)
			if err != nil {
				t.Fatal(err)
			}
			var id string
			if err := repo.ww.conn.QueryRowContext(context.Background(), "SELECT id FROM gorp_migrations LIMIT 1").Scan(&id); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.ww.conn.ExecContext(context.Background(), "UPDATE gorp_migrations SET applied_at=? WHERE id=?", stamp, id); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.ww.conn.ExecContext(context.Background(), "CREATE TABLE preserved_probe (value TEXT)"); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.ww.conn.ExecContext(context.Background(), "INSERT INTO preserved_probe VALUES ('keep')"); err != nil {
				t.Fatal(err)
			}
			_ = repo.Close()
			for i := 0; i < 2; i++ {
				repo, err = New(SQLite, path)
				if err != nil {
					t.Fatalf("reopen %d: %v", i+1, err)
				}
				var got, value string
				var count int
				if err := repo.ww.conn.QueryRowContext(context.Background(), "SELECT CAST(applied_at AS TEXT) FROM gorp_migrations WHERE id=?", id).Scan(&got); err != nil {
					t.Fatal(err)
				}
				expected, err := time.Parse("2006-01-02 15:04:05 -0700", strings.Join(strings.Fields(stamp)[:3], " "))
				if err != nil {
					t.Fatal(err)
				}
				actual, err := time.Parse(time.RFC3339Nano, got)
				if err != nil {
					t.Fatal(err)
				}
				if !actual.Equal(expected) {
					t.Errorf("timestamp instant changed: %s -> %s", stamp, got)
				}
				if err := repo.ww.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM gorp_migrations").Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Errorf("migration history count=%d", count)
				}
				if err := repo.ww.conn.QueryRowContext(context.Background(), "SELECT value FROM preserved_probe").Scan(&value); err != nil {
					t.Fatal(err)
				}
				if value != "keep" {
					t.Errorf("user table changed: %q", value)
				}
				_ = repo.Close()
			}
		})
	}
}

func TestSQLiteValidMigrationTimestampUnchanged(t *testing.T) {
	for _, stamp := range []string{"2026-11-13 17:51:45.116244512", "2026-11-13T17:51:45.116244512+05:30", "2026-11-13 17:51:45.116244512 +0530 IST m=+12.169086956"} {
		t.Run(stamp, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "asset.db")
			repo, err := New(SQLite, path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repo.ww.conn.ExecContext(context.Background(), "UPDATE gorp_migrations SET applied_at=?", stamp); err != nil {
				t.Fatal(err)
			}
			_ = repo.Close()
			repo, err = New(SQLite, path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = repo.Close() }()
			var got string
			if err := repo.ww.conn.QueryRowContext(context.Background(), "SELECT CAST(applied_at AS TEXT) FROM gorp_migrations").Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != stamp {
				t.Errorf("valid history changed: %q -> %q", stamp, got)
			}
		})
	}
}

func TestSQLiteUnknownMigrationTimestampUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.db")
	repo, err := New(SQLite, path)
	if err != nil {
		t.Fatal(err)
	}
	bad := "2026-99-13 17:51:45 +0530 +0530 m=+12.169086956"
	if _, err := repo.ww.conn.ExecContext(context.Background(), "UPDATE gorp_migrations SET applied_at=?", bad); err != nil {
		t.Fatal(err)
	}
	_ = repo.Close()
	if repo, err = New(SQLite, path); err == nil {
		_ = repo.Close()
		t.Fatal("invalid timestamp unexpectedly accepted")
	}
	db, err := sql.Open(SQLite, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var got string
	if err := db.QueryRow("SELECT CAST(applied_at AS TEXT) FROM gorp_migrations").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != bad {
		t.Errorf("unknown history changed: %q", got)
	}
}

func TestSQLiteMigrationTimestampRepairRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.db")
	repo, err := New(SQLite, path)
	if err != nil {
		t.Fatal(err)
	}
	stamp := "2026-11-13 17:51:45.116244512 +0530 +0530 m=+12.169086956"
	if _, err := repo.ww.conn.ExecContext(context.Background(), "UPDATE gorp_migrations SET applied_at=?", stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ww.conn.ExecContext(context.Background(), "CREATE TRIGGER prevent_history_update BEFORE UPDATE ON gorp_migrations BEGIN SELECT RAISE(ABORT, 'repair blocked'); END"); err != nil {
		t.Fatal(err)
	}
	_ = repo.Close()
	if repo, err = New(SQLite, path); err == nil {
		_ = repo.Close()
		t.Fatal("blocked repair unexpectedly succeeded")
	} else if !strings.Contains(err.Error(), "repair blocked") {
		t.Fatalf("unexpected error: %v", err)
	}
	db, err := sql.Open(SQLite, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var got string
	if err := db.QueryRow("SELECT CAST(applied_at AS TEXT) FROM gorp_migrations").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != stamp {
		t.Errorf("failed repair changed timestamp: %q", got)
	}
}
