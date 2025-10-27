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
	`)
	return err
}

// Queries provides prepared query helpers. Safe for concurrent use.
type Queries struct {
	db *sql.DB

	// Core prepared statements
	stmtEntityByID          *sql.Stmt
	stmtEntityIDByTypeValue *sql.Stmt
	stmtEntityIDByAssetPK   *sql.Stmt
	stmtRefRowByEntityTable *sql.Stmt

	// Cache of "select asset by id" statements, keyed by table name.
	mu         sync.RWMutex
	assetStmts map[string]*sql.Stmt
}

// NewQueries prepares the core statements. Additional per-table statements are prepared lazily.
func NewQueries(db *sql.DB) (*Queries, error) {
	r := &Queries{db: db, assetStmts: make(map[string]*sql.Stmt)}

	var err error
	if r.stmtEntityByID, err = db.Prepare(`
SELECT e.entity_id, t.name, e.display_value, e.attrs
FROM entities e
JOIN entity_type_lu t ON t.id = e.type_id
WHERE e.entity_id = ?`); err != nil {
		return nil, err
	}

	// Lookup by asset type + content (display_value). Normalization is handled outside for types that need it.
	if r.stmtEntityIDByTypeValue, err = db.Prepare(`
SELECT e.entity_id
FROM entities e
JOIN entity_type_lu t ON t.id = e.type_id
WHERE t.name = ? AND e.display_value = ? LIMIT 1`); err != nil {
		return nil, err
	}

	// Find entity by asset primary key (table_name, row_id) via entity_ref.
	if r.stmtEntityIDByAssetPK, err = db.Prepare(`
SELECT entity_id
FROM entity_ref
WHERE table_name = ? AND row_id = ?
LIMIT 1`); err != nil {
		return nil, err
	}

	// Map entity -> row_id in a specific table_name (for the entity's concrete asset).
	if r.stmtRefRowByEntityTable, err = db.Prepare(`
SELECT row_id
FROM entity_ref
WHERE entity_id = ? AND table_name = ?
LIMIT 1`); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *Queries) Close() error {
	var first error
	for _, st := range []*sql.Stmt{r.stmtEntityByID, r.stmtEntityIDByTypeValue, r.stmtEntityIDByAssetPK, r.stmtRefRowByEntityTable} {
		if st != nil {
			if err := st.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	r.mu.Lock()
	for _, st := range r.assetStmts {
		_ = st.Close()
	}
	r.assetStmts = nil
	r.mu.Unlock()
	return first
}

func (r *Queries) prepNamed(ctx context.Context, key, sqlText string) (*sql.Stmt, error) {
	// Reuse existing per-table cache map for simplicity (key namespace differs).
	return r.getOrPrepare(ctx, key, sqlText)
}

func (r *Queries) getOrPrepare(ctx context.Context, key, sqlText string) (*sql.Stmt, error) {
	r.mu.RLock()
	st := r.assetStmts[key]
	r.mu.RUnlock()
	if st != nil {
		return st, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// double check
	if st = r.assetStmts[key]; st != nil {
		return st, nil
	}
	ps, err := r.db.PrepareContext(ctx, sqlText)
	if err != nil {
		return nil, err
	}
	r.assetStmts[key] = ps
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
