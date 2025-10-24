// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"fmt"
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

stmts, err := SeedAndPrepareAll(ctx, db, SeedOptions{RefreshTemplates: false})
if err != nil { panic(err) }
defer stmts.Close()

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
		PRAGMA journal_mode = WAL;
		PRAGMA synchronous = NORMAL;
		PRAGMA foreign_keys = ON;
		PRAGMA temp_store = MEMORY;
		PRAGMA cache_size = -1048576; -- ~1 GiB if RAM allows
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

// --- Template catalog seeding ---

type SeedOptions struct {
	// If true, always overwrite the sql text in sql_templates (INSERT OR REPLACE).
	// If false, only insert when missing (INSERT OR IGNORE).
	RefreshTemplates bool
}

// Statements holds prepared handles for every helper
type Statements struct {
	UpsertAccountStmt          *sql.Stmt
	UpsertAutnumRecordStmt     *sql.Stmt
	UpsertAutonomousSystemStmt *sql.Stmt
	UpsertContactRecordStmt    *sql.Stmt
	UpsertDomainRecordStmt     *sql.Stmt
	UpsertFileStmt             *sql.Stmt
	UpsertFQDNStmt             *sql.Stmt
	UpsertFundsTransferStmt    *sql.Stmt
	UpsertIdentifierStmt       *sql.Stmt
	UpsertIPAddressStmt        *sql.Stmt
	UpsertIPNetRecordStmt      *sql.Stmt
	UpsertLocationStmt         *sql.Stmt
	UpsertNetblockStmt         *sql.Stmt
	UpsertOrganizationStmt     *sql.Stmt
	UpsertPersonStmt           *sql.Stmt
	UpsertPhoneStmt            *sql.Stmt
	UpsertProductStmt          *sql.Stmt
	UpsertProductReleaseStmt   *sql.Stmt
	UpsertServiceStmt          *sql.Stmt
	UpsertTLSCertificateStmt   *sql.Stmt
	UpsertURLStmt              *sql.Stmt
	EnsureEdgeStmt             *sql.Stmt
	UpsertTagStmt              *sql.Stmt
	TagEntityStmt              *sql.Stmt
	TagEdgeStmt                *sql.Stmt
}

func (s *Statements) Close() {
	for _, st := range []*sql.Stmt{
		s.UpsertAccountStmt, s.UpsertAutnumRecordStmt, s.UpsertAutonomousSystemStmt, s.UpsertContactRecordStmt,
		s.UpsertDomainRecordStmt, s.UpsertFileStmt, s.UpsertFQDNStmt, s.UpsertFundsTransferStmt, s.UpsertIdentifierStmt,
		s.UpsertIPAddressStmt, s.UpsertIPNetRecordStmt, s.UpsertLocationStmt, s.UpsertNetblockStmt, s.UpsertOrganizationStmt,
		s.UpsertPersonStmt, s.UpsertPhoneStmt, s.UpsertProductStmt, s.UpsertProductReleaseStmt, s.UpsertServiceStmt,
		s.UpsertTLSCertificateStmt, s.UpsertURLStmt, s.EnsureEdgeStmt, s.UpsertTagStmt, s.TagEntityStmt, s.TagEdgeStmt,
	} {
		if st != nil {
			_ = st.Close()
		}
	}
}

// SeedAndPrepareAll inserts every helper into sql_templates (idempotent) and prepares them.
func SeedAndPrepareAll(ctx context.Context, db *sql.DB, opt SeedOptions) (*Statements, error) {
	if err := ensureCatalog(ctx, db); err != nil {
		return nil, err
	}
	if err := seedCatalog(ctx, db, opt.RefreshTemplates); err != nil {
		return nil, err
	}
	return prepareAll(ctx, db)
}

func ensureCatalog(ctx context.Context, db *sql.DB) error {
	// sql_templates should exist from migration; create defensively if missing.
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS sql_templates (
  name TEXT PRIMARY KEY,
  sql  TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
);
`)
	return err
}

func seedCatalog(ctx context.Context, db *sql.DB, refresh bool) error {
	mode := "INSERT OR IGNORE"
	if refresh {
		mode = "INSERT OR REPLACE"
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	q := mode + ` INTO sql_templates(name, sql, updated_at) VALUES (?, ?, ?)`
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")

	for name, sqlText := range allTemplates() {
		if strings.TrimSpace(sqlText) == "" {
			return fmt.Errorf("empty template: %s", name)
		}
		if _, err := tx.ExecContext(ctx, q, name, sqlText, now); err != nil {
			return fmt.Errorf("seed %s: %w", name, err)
		}
	}
	return tx.Commit()
}

func prepareAll(ctx context.Context, db *sql.DB) (*Statements, error) {
	load := func(name string) (string, error) {
		var s string
		err := db.QueryRowContext(ctx, `SELECT sql FROM sql_templates WHERE name=?`, name).Scan(&s)
		return s, err
	}
	prep := func(name string) (*sql.Stmt, error) {
		s, err := load(name)
		if err != nil {
			return nil, fmt.Errorf("load template %s: %w", name, err)
		}
		return db.PrepareContext(ctx, s)
	}

	st := &Statements{}
	var err error

	if st.UpsertAccountStmt, err = prep("upsert_account"); err != nil {
		return nil, err
	}
	if st.UpsertAutnumRecordStmt, err = prep("upsert_autnumrecord"); err != nil {
		return nil, err
	}
	if st.UpsertAutonomousSystemStmt, err = prep("upsert_autonomoussystem"); err != nil {
		return nil, err
	}
	if st.UpsertContactRecordStmt, err = prep("upsert_contactrecord"); err != nil {
		return nil, err
	}
	if st.UpsertDomainRecordStmt, err = prep("upsert_domainrecord"); err != nil {
		return nil, err
	}
	if st.UpsertFileStmt, err = prep("upsert_file"); err != nil {
		return nil, err
	}
	if st.UpsertFQDNStmt, err = prep("upsert_fqdn"); err != nil {
		return nil, err
	}
	if st.UpsertFundsTransferStmt, err = prep("upsert_fundstransfer"); err != nil {
		return nil, err
	}
	if st.UpsertIdentifierStmt, err = prep("upsert_identifier"); err != nil {
		return nil, err
	}
	if st.UpsertIPAddressStmt, err = prep("upsert_ipaddress"); err != nil {
		return nil, err
	}
	if st.UpsertIPNetRecordStmt, err = prep("upsert_ipnetrecord"); err != nil {
		return nil, err
	}
	if st.UpsertLocationStmt, err = prep("upsert_location"); err != nil {
		return nil, err
	}
	if st.UpsertNetblockStmt, err = prep("upsert_netblock"); err != nil {
		return nil, err
	}
	if st.UpsertOrganizationStmt, err = prep("upsert_organization"); err != nil {
		return nil, err
	}
	if st.UpsertPersonStmt, err = prep("upsert_person"); err != nil {
		return nil, err
	}
	if st.UpsertPhoneStmt, err = prep("upsert_phone"); err != nil {
		return nil, err
	}
	if st.UpsertProductStmt, err = prep("upsert_product"); err != nil {
		return nil, err
	}
	if st.UpsertProductReleaseStmt, err = prep("upsert_productrelease"); err != nil {
		return nil, err
	}
	if st.UpsertServiceStmt, err = prep("upsert_service"); err != nil {
		return nil, err
	}
	if st.UpsertTLSCertificateStmt, err = prep("upsert_tlscertificate"); err != nil {
		return nil, err
	}
	if st.UpsertURLStmt, err = prep("upsert_url"); err != nil {
		return nil, err
	}
	if st.EnsureEdgeStmt, err = prep("ensure_edge"); err != nil {
		return nil, err
	}
	if st.UpsertTagStmt, err = prep("upsert_tag"); err != nil {
		return nil, err
	}
	if st.TagEntityStmt, err = prep("tag_entity"); err != nil {
		return nil, err
	}
	if st.TagEdgeStmt, err = prep("tag_edge"); err != nil {
		return nil, err
	}
	return st, nil
}

func allTemplates() map[string]string {
	return map[string]string{
		"upsert_account":          tmplUpsertAccount,
		"upsert_autnumrecord":     tmplUpsertAutnumRecord,
		"upsert_autonomoussystem": tmplUpsertAutonomousSystem,
		"upsert_contactrecord":    tmplUpsertContactRecord,
		"upsert_domainrecord":     tmplUpsertDomainRecord,
		"upsert_file":             tmplUpsertFile,
		"upsert_fqdn":             tmplUpsertFQDN,
		"upsert_fundstransfer":    tmplUpsertFundsTransfer,
		"upsert_identifier":       tmplUpsertIdentifier,
		"upsert_ipaddress":        tmplUpsertIPAddress,
		"upsert_ipnetrecord":      tmplUpsertIPNetRecord,
		"upsert_location":         tmplUpsertLocation,
		"upsert_netblock":         tmplUpsertNetblock,
		"upsert_organization":     tmplUpsertOrganization,
		"upsert_person":           tmplUpsertPerson,
		"upsert_phone":            tmplUpsertPhone,
		"upsert_product":          tmplUpsertProduct,
		"upsert_productrelease":   tmplUpsertProductRelease,
		"upsert_service":          tmplUpsertService,
		"upsert_tlscertificate":   tmplUpsertTLSCertificate,
		"upsert_url":              tmplUpsertURL,
		"ensure_edge":             tmplEnsureEdge,
		"upsert_tag":              tmplUpsertTag,
		"tag_entity":              tmplTagEntity,
		"tag_edge":                tmplTagEdge,
	}
}
