// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestReopenWithUnnamedLocalZone(t *testing.T) {
	orig := time.Local
	time.Local = time.FixedZone("", 19800)
	defer func() { time.Local = orig }()

	fpath := filepath.Join(t.TempDir(), "db.sqlite")
	for i := 0; i < 2; i++ {
		repo, err := New(SQLite, fpath)
		if err != nil {
			t.Fatalf("open %d: %v", i+1, err)
		}
		if err := repo.Close(); err != nil {
			t.Fatalf("close %d: %v", i+1, err)
		}
	}
}

func TestReopenRepairsLegacyMigrationTimestamps(t *testing.T) {
	cases := map[string]string{
		"unnamed zone with monotonic suffix": "2026-11-13 17:51:45.116244512 +0530 +0530 m=+12.169086956",
		"named zone with monotonic suffix":   "2026-11-13 17:51:45.116244512 +0530 IST m=+12.169086956",
		"utc with monotonic suffix":          "2026-11-13 12:21:45.116244512 +0000 UTC m=+0.500000001",
		"unnamed zone without suffix":        "2026-11-13 17:51:45.116244512 +0530 +0530",
		"whole seconds":                      "2026-11-13 17:51:45 +0530 +0530 m=+1.5",
	}
	want := time.Date(2026, 11, 13, 12, 21, 45, 0, time.UTC)

	for name, legacy := range cases {
		t.Run(name, func(t *testing.T) {
			fpath := filepath.Join(t.TempDir(), "db.sqlite")
			repo, err := New(SQLite, fpath)
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.Close(); err != nil {
				t.Fatal(err)
			}

			raw, err := sql.Open(SQLite, fpath)
			if err != nil {
				t.Fatal(err)
			}
			var before int
			if err := raw.QueryRow(`SELECT count(*) FROM gorp_migrations`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			_, err = raw.Exec(`UPDATE gorp_migrations SET applied_at = ?`, legacy)
			_ = raw.Close()
			if err != nil {
				t.Fatal(err)
			}

			// Opening more than once must keep the same migration records.
			for i := 0; i < 3; i++ {
				repo, err = New(SQLite, fpath)
				if err != nil {
					t.Fatalf("open %d: %v", i+1, err)
				}
				if err := repo.Close(); err != nil {
					t.Fatal(err)
				}
			}

			raw, err = sql.Open(SQLite, fpath+"?_time_format=sqlite")
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()

			rows, err := raw.Query(`SELECT id, applied_at FROM gorp_migrations`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			n := 0
			for rows.Next() {
				var id string
				var applied time.Time
				if err := rows.Scan(&id, &applied); err != nil {
					t.Fatalf("scan applied_at: %v", err)
				}
				if got := applied.UTC().Truncate(time.Second); !got.Equal(want) {
					t.Fatalf("%s: applied_at %v, want instant %v", id, got, want)
				}
				n++
			}
			if n != before {
				t.Fatalf("migration records: got %d, want %d", n, before)
			}
		})
	}
}
