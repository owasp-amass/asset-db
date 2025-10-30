// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

/*
Usage:

db, _ := sql.Open("sqlite3", "file:amass.db?_busy_timeout=15000&_foreign_keys=on&_journal_mode=WAL")
ctx := context.Background()
if err := ApplyPragmas(ctx, db); err != nil { panic(err) }

queries, err := NewQueries(db)
if err != nil { panic(err) }
defer queries.Close()

eidFQDN, _ := stmts.UpsertFQDN(ctx, "www.example.com", `{"source":"dns"}`)
eidIP,   _ := stmts.UpsertIP(ctx, "93.184.216.34", "IPv4", `{}`)
edgeID,  _ := stmts.EnsureEdge(ctx, "RESOLVES_TO", eidFQDN, eidIP, `{"ttl":300}`)
mapID,   _ := stmts.TagEntity(ctx, eidFQDN, "amass", "scope", "public", `{"note":"seed"}`)
*/

func ApplyPragmas(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
		PRAGMA foreign_keys = ON;
		PRAGMA journal_mode = WAL;
		PRAGMA synchronous = NORMAL;         -- tweak to FULL for extra durability
		PRAGMA temp_store = MEMORY;
		PRAGMA mmap_size = 268435456;        -- 256 MiB map if available
		PRAGMA page_size = 4096;
		PRAGMA cache_size = -1048576;        -- ~1 GiB cache (negative = KiB units)
		PRAGMA journal_mode = WAL;
		PRAGMA busy_timeout = 5000;  		 -- or higher under heavy load
	`)
	return err
}

// Queries provides prepared query helpers. Safe for concurrent use.
type Queries struct {
	db *sql.DB
	// Cache of "select asset by id" statements, keyed by table name.
	mu    sync.RWMutex
	stmts map[string]*sql.Stmt
}

// NewQueries prepares the core statements. Additional per-table statements are prepared lazily.
func NewQueries(db *sql.DB) (*Queries, error) {
	return &Queries{db: db, stmts: make(map[string]*sql.Stmt)}, nil
}

func (r *Queries) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, st := range r.stmts {
		if err := st.Close(); err != nil {
			return err
		}
	}

	r.stmts = nil
	return nil
}

func (r *Queries) getOrPrepare(ctx context.Context, key, sqlText string) (*sql.Stmt, error) {
	r.mu.RLock()
	st := r.stmts[key]
	r.mu.RUnlock()
	if st != nil {
		return st, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// double check
	if st = r.stmts[key]; st != nil {
		return st, nil
	}

	ps, err := r.db.PrepareContext(ctx, sqlText)
	if err != nil {
		return nil, err
	}

	r.stmts[key] = ps
	return ps, nil
}

// ------------------------------ Scan Utilities ------------------------------

// parseTS converts a *string timestamp into *time.Time (RFC3339 or SQLite default format).
// If parsing fails, returns nil (non-fatal for presentation purposes).
func parseTS(s *string) *time.Time {
	if s == nil {
		return nil
	}
	str := strings.TrimSpace(*s)
	if str == "" {
		return nil
	}
	// Try SQLite's default (YYYY-MM-DD HH:MM:SS.SSS) then RFC3339
	layouts := []string{
		"2006-01-02 15:04:05.000",
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02 15:04:05",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, str); err == nil {
			return &t
		}
	}
	return nil
}
