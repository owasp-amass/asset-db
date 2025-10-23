// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
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

// --- Small wrappers that return IDs (you can add more as needed) ---

func (s *Statements) UpsertFQDN(ctx context.Context, fqdn, attrsJSON string) (int64, error) {
	row := s.UpsertFQDNStmt.QueryRowContext(ctx,
		sql.Named("fqdn_text", fqdn),
		sql.Named("attrs", attrsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (s *Statements) UpsertIP(ctx context.Context, ip, ipVersion, attrsJSON string) (int64, error) {
	row := s.UpsertIPAddressStmt.QueryRowContext(ctx,
		sql.Named("ip_version", ipVersion),
		sql.Named("ip_address_text", ip),
		sql.Named("attrs", attrsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (s *Statements) EnsureEdge(ctx context.Context, etype string, fromID, toID int64, contentJSON string) (int64, error) {
	row := s.EnsureEdgeStmt.QueryRowContext(ctx,
		sql.Named("etype_name", etype),
		sql.Named("from_entity_id", fromID),
		sql.Named("to_entity_id", toID),
		sql.Named("content", contentJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (s *Statements) TagEntity(ctx context.Context, entityID int64, ns, name, value, detailsJSON string) (int64, error) {
	row := s.TagEntityStmt.QueryRowContext(ctx,
		sql.Named("entity_id", entityID),
		sql.Named("namespace", ns),
		sql.Named("name", name),
		sql.Named("value", value),
		sql.Named("details", detailsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (s *Statements) TagEdge(ctx context.Context, edgeID int64, ns, name, value, detailsJSON string) (int64, error) {
	row := s.TagEdgeStmt.QueryRowContext(ctx,
		sql.Named("edge_id", edgeID),
		sql.Named("namespace", ns),
		sql.Named("name", name),
		sql.Named("value", value),
		sql.Named("details", detailsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

// --- All templates (verbatim SQL CTEs) ---

func allTemplates() map[string]string {
	// Each value is the exact WITH ... SELECT ... statement from your 02_upserts_sqlite.sql.
	// (To keep this file readable, they are trimmed and grouped. Add or tweak as you need.)
	return map[string]string{
		// Assets
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

		// Graph / tags
		"ensure_edge": tmplEnsureEdge,
		"upsert_tag":  tmplUpsertTag,
		"tag_entity":  tmplTagEntity,
		"tag_edge":    tmplTagEdge,
	}
}

// ============================================================================
// OWASP Amass — UPSERT helpers for SQLite (3.35+ for RETURNING)
// - Execute snippets ad hoc (prepare/step/finalize) to get ids back.
// - Bind parameters shown as :named; JSON params may be NULL (treated as '{}').
// - No-op-aware updates: ON CONFLICT ... DO UPDATE ... WHERE <changed>
// - Entities: each upsert also registers a row in entities + entity_ref.
// ============================================================================

// ---------------------------------------------------------------------------
// Helper comment blocks you might reuse inline
// ---------------------------------------------------------------------------
// (Get or create entity type id)
//   WITH ensure_type AS (
//     INSERT INTO entity_type_lu(name) VALUES (:etype_name)
//     ON CONFLICT(name) DO NOTHING
//     RETURNING id
//   ),
//   type_id AS (
//     SELECT id FROM ensure_type
//     UNION ALL SELECT id FROM entity_type_lu WHERE name=:etype_name LIMIT 1
//   )

// (Generic entity+ref registration tail; assumes CTEs: type_id, row_id_cte)
//   , ent_ins AS (
//       INSERT INTO entities(type_id, display_value, attrs)
//       SELECT (SELECT id FROM type_id), :display_value, coalesce(:attrs,'{}')
//       ON CONFLICT(type_id, display_value) DO UPDATE SET
//         attrs = CASE
//           WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
//           THEN json_patch(entities.attrs, coalesce(:attrs,'{}'))
//           ELSE entities.attrs
//         END,
//         updated_at = CASE
//           WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
//           THEN strftime('%Y-%m-%d %H:%M:%f','now')
//           ELSE entities.updated_at
//         END
//       WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
//       RETURNING entity_id
//     ),
//     ent_id AS (
//       SELECT entity_id FROM ent_ins
//       UNION ALL
//       SELECT entity_id FROM entities
//       WHERE type_id = (SELECT id FROM type_id) AND display_value = :display_value
//       LIMIT 1
//     ),
//     ref_up AS (
//       INSERT INTO entity_ref(entity_id, table_name, row_id)
//       VALUES ((SELECT entity_id FROM ent_id), :table_name, (SELECT row_id FROM row_id_cte))
//       ON CONFLICT(table_name, row_id) DO UPDATE SET
//         entity_id  = excluded.entity_id,
//         updated_at = strftime('%Y-%m-%d %H:%M:%f','now')
//       WHERE entity_ref.entity_id IS NOT excluded.entity_id
//     )
//   SELECT entity_id FROM ent_id;

// ============================================================================
// Assets
// ============================================================================

// ACCOUNT --------------------------------------------------------------------
// Params: :unique_id, :account_type, :username, :account_number, :balance, :active, :attrs
const tmplUpsertAccount = `
WITH
  row_try AS (
    INSERT INTO account(unique_id, account_type, username, account_number, balance, active)
    VALUES (:unique_id, :account_type, :username, :account_number, :balance, :active)
    ON CONFLICT(unique_id) DO UPDATE SET
      account_type   = COALESCE(excluded.account_type,   account.account_type),
      username       = COALESCE(excluded.username,       account.username),
      account_number = COALESCE(excluded.account_number, account.account_number),
      balance        = COALESCE(excluded.balance,        account.balance),
      active         = COALESCE(excluded.active,         account.active),
      updated_at     = CASE WHEN
        (excluded.account_type   IS NOT account.account_type) OR
        (excluded.username       IS NOT account.username) OR
        (excluded.account_number IS NOT account.account_number) OR
        (excluded.balance        IS NOT account.balance) OR
        (excluded.active         IS NOT account.active)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE account.updated_at END
    WHERE (excluded.account_type   IS NOT account.account_type) OR
          (excluded.username       IS NOT account.username) OR
          (excluded.account_number IS NOT account.account_number) OR
          (excluded.balance        IS NOT account.balance) OR
          (excluded.active         IS NOT account.active)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM account WHERE unique_id = :unique_id LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('account')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (
    SELECT id FROM ensure_type
    UNION ALL SELECT id FROM entity_type_lu WHERE name='account' LIMIT 1
  ),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :unique_id, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (
    SELECT entity_id FROM ent_ins
    UNION ALL SELECT entity_id FROM entities
    WHERE type_id=(SELECT id FROM type_id) AND display_value=:unique_id LIMIT 1
  ),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id), 'account', (SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

// AUTNUMRECORD ---------------------------------------------------------------
// Params: :handle, :asn, :record_name, :record_status, :created_date, :updated_date, :whois_server, :attrs
const tmplUpsertAutnumRecord = `
WITH
  row_try AS (
    INSERT INTO autnumrecord(handle, asn, record_name, record_status, created_date, updated_date, whois_server)
    VALUES (:handle, :asn, :record_name, :record_status, :created_date, :updated_date, :whois_server)
    ON CONFLICT(handle) DO UPDATE SET
      asn           = COALESCE(excluded.asn,           autnumrecord.asn),
      record_name   = COALESCE(excluded.record_name,   autnumrecord.record_name),
      record_status = COALESCE(excluded.record_status, autnumrecord.record_status),
      created_date  = COALESCE(excluded.created_date,  autnumrecord.created_date),
      updated_date  = COALESCE(excluded.updated_date,  autnumrecord.updated_date),
      whois_server  = COALESCE(excluded.whois_server,  autnumrecord.whois_server),
      updated_at    = CASE WHEN
        (excluded.asn           IS NOT autnumrecord.asn) OR
        (excluded.record_name   IS NOT autnumrecord.record_name) OR
        (excluded.record_status IS NOT autnumrecord.record_status) OR
        (excluded.created_date  IS NOT autnumrecord.created_date) OR
        (excluded.updated_date  IS NOT autnumrecord.updated_date) OR
        (excluded.whois_server  IS NOT autnumrecord.whois_server)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE autnumrecord.updated_at END
    WHERE (excluded.asn           IS NOT autnumrecord.asn) OR
          (excluded.record_name   IS NOT autnumrecord.record_name) OR
          (excluded.record_status IS NOT autnumrecord.record_status) OR
          (excluded.created_date  IS NOT autnumrecord.created_date) OR
          (excluded.updated_date  IS NOT autnumrecord.updated_date) OR
          (excluded.whois_server  IS NOT autnumrecord.whois_server)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM autnumrecord WHERE handle=:handle LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('autnumrecord')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='autnumrecord' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :handle, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
              THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
                   THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins
             UNION ALL SELECT entity_id FROM entities
             WHERE type_id=(SELECT id FROM type_id) AND display_value=:handle LIMIT 1),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id),'autnumrecord',(SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

// AUTONOMOUS SYSTEM ----------------------------------------------------------
// Params: :asn, :attrs
const tmplUpsertAutonomousSystem = `
WITH
  row_try AS (
    INSERT INTO autonomoussystem(asn) VALUES (:asn)
    ON CONFLICT(asn) DO NOTHING
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM autonomoussystem WHERE asn=:asn LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('autonomoussystem')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='autonomoussystem' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), 'AS'||CAST(:asn AS TEXT), coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
              THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
                   THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins
             UNION ALL SELECT entity_id FROM entities
             WHERE type_id=(SELECT id FROM type_id) AND display_value='AS'||CAST(:asn AS TEXT) LIMIT 1),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id),'autonomoussystem',(SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

// CONTACTRECORD --------------------------------------------------------------
// Params: :discovered_at, :attrs
const tmplUpsertContactRecord = `
WITH
  row_try AS (
    INSERT INTO contactrecord(discovered_at) VALUES (:discovered_at)
    ON CONFLICT(discovered_at) DO NOTHING
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM contactrecord WHERE discovered_at=:discovered_at LIMIT 1),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('contactrecord')
    ON CONFLICT(name) DO NOTHING RETURNING id
  ),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='contactrecord' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :discovered_at, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins
             UNION ALL SELECT entity_id FROM entities
             WHERE type_id=(SELECT id FROM type_id) AND display_value=:discovered_at LIMIT 1),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id),'contactrecord',(SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

// DOMAINRECORD ---------------------------------------------------------------
// Params: :domain_text, :record_name, :raw_record, :record_status, :punycode, :extension,
//
//	:created_date, :updated_date, :expiration_date, :whois_server, :attrs
const tmplUpsertDomainRecord = `
WITH
  row_try AS (
    INSERT INTO domainrecord(domain, record_name, raw_record, record_status, punycode, extension,
                             created_date, updated_date, expiration_date, whois_server)
    VALUES (:domain_text, :record_name, :raw_record, :record_status, :punycode, :extension,
            :created_date, :updated_date, :expiration_date, :whois_server)
    ON CONFLICT(domain_norm) DO UPDATE SET
      record_name   = COALESCE(excluded.record_name,   domainrecord.record_name),
      raw_record    = COALESCE(excluded.raw_record,    domainrecord.raw_record),
      record_status = COALESCE(excluded.record_status, domainrecord.record_status),
      punycode      = COALESCE(excluded.punycode,      domainrecord.punycode),
      extension     = COALESCE(excluded.extension,     domainrecord.extension),
      created_date  = COALESCE(excluded.created_date,  domainrecord.created_date),
      updated_date  = COALESCE(excluded.updated_date,  domainrecord.updated_date),
      expiration_date = COALESCE(excluded.expiration_date, domainrecord.expiration_date),
      whois_server  = COALESCE(excluded.whois_server,  domainrecord.whois_server),
      updated_at    = CASE WHEN
         (excluded.record_name   IS NOT domainrecord.record_name) OR
         (excluded.raw_record    IS NOT domainrecord.raw_record) OR
         (excluded.record_status IS NOT domainrecord.record_status) OR
         (excluded.punycode      IS NOT domainrecord.punycode) OR
         (excluded.extension     IS NOT domainrecord.extension) OR
         (excluded.created_date  IS NOT domainrecord.created_date) OR
         (excluded.updated_date  IS NOT domainrecord.updated_date) OR
         (excluded.expiration_date IS NOT domainrecord.expiration_date) OR
         (excluded.whois_server  IS NOT domainrecord.whois_server)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE domainrecord.updated_at END
    WHERE (excluded.record_name   IS NOT domainrecord.record_name) OR
          (excluded.raw_record    IS NOT domainrecord.raw_record) OR
          (excluded.record_status IS NOT domainrecord.record_status) OR
          (excluded.punycode      IS NOT domainrecord.punycode) OR
          (excluded.extension     IS NOT domainrecord.extension) OR
          (excluded.created_date  IS NOT domainrecord.created_date) OR
          (excluded.updated_date  IS NOT domainrecord.updated_date) OR
          (excluded.expiration_date IS NOT domainrecord.expiration_date) OR
          (excluded.whois_server  IS NOT domainrecord.whois_server)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM domainrecord WHERE domain_norm = lower(:domain_text) LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('domainrecord')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (
    SELECT id FROM ensure_type
    UNION ALL SELECT id FROM entity_type_lu WHERE name='domainrecord' LIMIT 1
  ),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), lower(:domain_text), coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}'))
        ELSE entities.attrs
      END,
      updated_at = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now')
        ELSE entities.updated_at
      END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (
    SELECT entity_id FROM ent_ins
    UNION ALL
    SELECT entity_id FROM entities
    WHERE type_id = (SELECT id FROM type_id) AND display_value = lower(:domain_text)
    LIMIT 1
  ),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id), 'domainrecord', (SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name, row_id) DO UPDATE SET
      entity_id  = excluded.entity_id,
      updated_at = strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

// FILE -----------------------------------------------------------------------
// Params: :file_url, :basename, :file_type, :attrs
const tmplUpsertFile = `
WITH
  row_try AS (
    INSERT INTO file(file_url, basename, file_type)
    VALUES (:file_url, :basename, :file_type)
    ON CONFLICT(file_url) DO UPDATE SET
      basename   = COALESCE(excluded.basename,  file.basename),
      file_type  = COALESCE(excluded.file_type, file.file_type),
      updated_at = CASE WHEN
        (excluded.basename IS NOT file.basename) OR
        (excluded.file_type IS NOT file.file_type)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE file.updated_at END
    WHERE (excluded.basename IS NOT file.basename) OR
          (excluded.file_type IS NOT file.file_type)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM file WHERE file_url=:file_url LIMIT 1),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('file')
    ON CONFLICT(name) DO NOTHING RETURNING id
  ),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='file' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :file_url, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins
             UNION ALL SELECT entity_id FROM entities
             WHERE type_id=(SELECT id FROM type_id) AND display_value=:file_url LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'file',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// FQDN -----------------------------------------------------------------------
// Params: :fqdn_text, :attrs
const tmplUpsertFQDN = `
WITH
  row_try AS (
    INSERT INTO fqdn(fqdn) VALUES (:fqdn_text)
    ON CONFLICT(fqdn_norm) DO NOTHING
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM fqdn WHERE fqdn_norm = lower(:fqdn_text) LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('fqdn')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (
    SELECT id FROM ensure_type
    UNION ALL SELECT id FROM entity_type_lu WHERE name='fqdn' LIMIT 1
  ),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), lower(:fqdn_text), coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}'))
        ELSE entities.attrs
      END,
      updated_at = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now')
        ELSE entities.updated_at
      END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (
    SELECT entity_id FROM ent_ins
    UNION ALL
    SELECT entity_id FROM entities
    WHERE type_id = (SELECT id FROM type_id) AND display_value = lower(:fqdn_text)
    LIMIT 1
  ),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id), 'fqdn', (SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name, row_id) DO UPDATE SET
      entity_id  = excluded.entity_id,
      updated_at = strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

// FUNDSTRANSFER --------------------------------------------------------------
// Params: :unique_id, :amount, :reference_number, :currency, :transfer_method, :exchange_date, :exchange_rate, :attrs
const tmplUpsertFundsTransfer = `
WITH
  row_try AS (
    INSERT INTO fundstransfer(unique_id, amount, reference_number, currency, transfer_method, exchange_date, exchange_rate)
    VALUES (:unique_id, :amount, :reference_number, :currency, :transfer_method, :exchange_date, :exchange_rate)
    ON CONFLICT(unique_id) DO UPDATE SET
      amount           = COALESCE(excluded.amount,           fundstransfer.amount),
      reference_number = COALESCE(excluded.reference_number, fundstransfer.reference_number),
      currency         = COALESCE(excluded.currency,         fundstransfer.currency),
      transfer_method  = COALESCE(excluded.transfer_method,  fundstransfer.transfer_method),
      exchange_date    = COALESCE(excluded.exchange_date,    fundstransfer.exchange_date),
      exchange_rate    = COALESCE(excluded.exchange_rate,    fundstransfer.exchange_rate),
      updated_at       = CASE WHEN
        (excluded.amount           IS NOT fundstransfer.amount) OR
        (excluded.reference_number IS NOT fundstransfer.reference_number) OR
        (excluded.currency         IS NOT fundstransfer.currency) OR
        (excluded.transfer_method  IS NOT fundstransfer.transfer_method) OR
        (excluded.exchange_date    IS NOT fundstransfer.exchange_date) OR
        (excluded.exchange_rate    IS NOT fundstransfer.exchange_rate)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE fundstransfer.updated_at END
    WHERE (excluded.amount           IS NOT fundstransfer.amount) OR
          (excluded.reference_number IS NOT fundstransfer.reference_number) OR
          (excluded.currency         IS NOT fundstransfer.currency) OR
          (excluded.transfer_method  IS NOT fundstransfer.transfer_method) OR
          (excluded.exchange_date    IS NOT fundstransfer.exchange_date) OR
          (excluded.exchange_rate    IS NOT fundstransfer.exchange_rate)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM fundstransfer WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('fundstransfer') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='fundstransfer' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :unique_id, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:unique_id LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'fundstransfer',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// IDENTIFIER -----------------------------------------------------------------
// Params: :id_type, :unique_id, :attrs
const tmplUpsertIdentifier = `WITH
  row_try AS (
    INSERT INTO identifier(id_type, unique_id) VALUES (:id_type, :unique_id)
    ON CONFLICT(unique_id) DO UPDATE SET
      id_type   = COALESCE(excluded.id_type, identifier.id_type),
      updated_at = CASE WHEN (excluded.id_type IS NOT identifier.id_type)
                   THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE identifier.updated_at END
    WHERE (excluded.id_type IS NOT identifier.id_type)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM identifier WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('identifier') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='identifier' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :unique_id, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins
             UNION ALL SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:unique_id LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'identifier',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// IPADDRESS ------------------------------------------------------------------
// Params: :ip_version, :ip_address_text, :attrs
const tmplUpsertIPAddress = `
WITH
  row_try AS (
    INSERT INTO ipaddress(ip_version, ip_address)
    VALUES (:ip_version, :ip_address_text)
    ON CONFLICT(ip_address) DO UPDATE SET
      ip_version = COALESCE(excluded.ip_version, ipaddress.ip_version),
      updated_at = CASE WHEN (excluded.ip_version IS NOT ipaddress.ip_version)
                   THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE ipaddress.updated_at END
    WHERE (excluded.ip_version IS NOT ipaddress.ip_version)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM ipaddress WHERE ip_address = :ip_address_text LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('ipaddress')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (
    SELECT id FROM ensure_type
    UNION ALL SELECT id FROM entity_type_lu WHERE name = 'ipaddress' LIMIT 1
  ),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :ip_address_text, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}'))
        ELSE entities.attrs
      END,
      updated_at = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (
    SELECT entity_id FROM ent_ins
    UNION ALL SELECT entity_id FROM entities
    WHERE type_id = (SELECT id FROM type_id) AND display_value = :ip_address_text
    LIMIT 1
  ),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id), 'ipaddress', (SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name, row_id) DO UPDATE SET
      entity_id  = excluded.entity_id,
      updated_at = strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

// IPNETRECORD ----------------------------------------------------------------
// Params: :record_cidr, :record_name, :ip_version, :handle, :method, :record_status,
//
//	:created_date, :updated_date, :whois_server, :parent_handle, :start_address, :end_address, :country, :attrs
const tmplUpsertIPNetRecord = `
WITH
  row_try AS (
    INSERT INTO ipnetrecord(
      record_cidr, record_name, ip_version, handle, method, record_status,
      created_date, updated_date, whois_server, parent_handle, start_address, end_address, country
    ) VALUES (
      :record_cidr, :record_name, :ip_version, :handle, :method, :record_status,
      :created_date, :updated_date, :whois_server, :parent_handle, :start_address, :end_address, :country
    )
    ON CONFLICT(record_cidr) DO UPDATE SET
      record_name   = COALESCE(excluded.record_name,   ipnetrecord.record_name),
      ip_version    = COALESCE(excluded.ip_version,    ipnetrecord.ip_version),
      handle        = COALESCE(excluded.handle,        ipnetrecord.handle),
      method        = COALESCE(excluded.method,        ipnetrecord.method),
      record_status = COALESCE(excluded.record_status, ipnetrecord.record_status),
      created_date  = COALESCE(excluded.created_date,  ipnetrecord.created_date),
      updated_date  = COALESCE(excluded.updated_date,  ipnetrecord.updated_date),
      whois_server  = COALESCE(excluded.whois_server,  ipnetrecord.whois_server),
      parent_handle = COALESCE(excluded.parent_handle, ipnetrecord.parent_handle),
      start_address = COALESCE(excluded.start_address, ipnetrecord.start_address),
      end_address   = COALESCE(excluded.end_address,   ipnetrecord.end_address),
      country       = COALESCE(excluded.country,       ipnetrecord.country),
      updated_at    = CASE WHEN
        (excluded.record_name IS NOT ipnetrecord.record_name) OR
        (excluded.ip_version  IS NOT ipnetrecord.ip_version) OR
        (excluded.handle      IS NOT ipnetrecord.handle) OR
        (excluded.method      IS NOT ipnetrecord.method) OR
        (excluded.record_status IS NOT ipnetrecord.record_status) OR
        (excluded.created_date IS NOT ipnetrecord.created_date) OR
        (excluded.updated_date IS NOT ipnetrecord.updated_date) OR
        (excluded.whois_server IS NOT ipnetrecord.whois_server) OR
        (excluded.parent_handle IS NOT ipnetrecord.parent_handle) OR
        (excluded.start_address IS NOT ipnetrecord.start_address) OR
        (excluded.end_address IS NOT ipnetrecord.end_address) OR
        (excluded.country IS NOT ipnetrecord.country)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE ipnetrecord.updated_at END
    WHERE (excluded.record_name IS NOT ipnetrecord.record_name) OR
          (excluded.ip_version  IS NOT ipnetrecord.ip_version) OR
          (excluded.handle      IS NOT ipnetrecord.handle) OR
          (excluded.method      IS NOT ipnetrecord.method) OR
          (excluded.record_status IS NOT ipnetrecord.record_status) OR
          (excluded.created_date IS NOT ipnetrecord.created_date) OR
          (excluded.updated_date IS NOT ipnetrecord.updated_date) OR
          (excluded.whois_server IS NOT ipnetrecord.whois_server) OR
          (excluded.parent_handle IS NOT ipnetrecord.parent_handle) OR
          (excluded.start_address IS NOT ipnetrecord.start_address) OR
          (excluded.end_address IS NOT ipnetrecord.end_address) OR
          (excluded.country IS NOT ipnetrecord.country)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM ipnetrecord WHERE record_cidr=:record_cidr OR handle=:handle LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('ipnetrecord')
    ON CONFLICT(name) DO NOTHING RETURNING id
  ),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='ipnetrecord' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :record_cidr, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:record_cidr LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'ipnetrecord',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// LOCATION -------------------------------------------------------------------
// Params: :city, :street_address, :country, :unit, :building, :province, :locality, :postal_code, :street_name, :building_number, :attrs
const tmplUpsertLocation = `
WITH
  row_try AS (
    INSERT INTO location(city, street_address, country, unit, building, province, locality, postal_code, street_name, building_number)
    VALUES (:city, :street_address, :country, :unit, :building, :province, :locality, :postal_code, :street_name, :building_number)
    ON CONFLICT(street_address) DO UPDATE SET
      city            = COALESCE(excluded.city,            location.city),
      country         = COALESCE(excluded.country,         location.country),
      unit            = COALESCE(excluded.unit,            location.unit),
      building        = COALESCE(excluded.building,        location.building),
      province        = COALESCE(excluded.province,        location.province),
      locality        = COALESCE(excluded.locality,        location.locality),
      postal_code     = COALESCE(excluded.postal_code,     location.postal_code),
      street_name     = COALESCE(excluded.street_name,     location.street_name),
      building_number = COALESCE(excluded.building_number, location.building_number),
      updated_at      = CASE WHEN
        (excluded.city            IS NOT location.city) OR
        (excluded.country         IS NOT location.country) OR
        (excluded.unit            IS NOT location.unit) OR
        (excluded.building        IS NOT location.building) OR
        (excluded.province        IS NOT location.province) OR
        (excluded.locality        IS NOT location.locality) OR
        (excluded.postal_code     IS NOT location.postal_code) OR
        (excluded.street_name     IS NOT location.street_name) OR
        (excluded.building_number IS NOT location.building_number)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE location.updated_at END
    WHERE (excluded.city            IS NOT location.city) OR
          (excluded.country         IS NOT location.country) OR
          (excluded.unit            IS NOT location.unit) OR
          (excluded.building        IS NOT location.building) OR
          (excluded.province        IS NOT location.province) OR
          (excluded.locality        IS NOT location.locality) OR
          (excluded.postal_code     IS NOT location.postal_code) OR
          (excluded.street_name     IS NOT location.street_name) OR
          (excluded.building_number IS NOT location.building_number)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM location WHERE street_address=:street_address LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('location') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='location' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :street_address, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:street_address LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'location',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// NETBLOCK -------------------------------------------------------------------
// Params: :netblock_cidr, :ip_version, :attrs
const tmplUpsertNetblock = `
WITH
  row_try AS (
    INSERT INTO netblock(netblock_cidr, ip_version) VALUES (:netblock_cidr, :ip_version)
    ON CONFLICT(netblock_cidr) DO UPDATE SET
      ip_version = COALESCE(excluded.ip_version, netblock.ip_version),
      updated_at = CASE WHEN (excluded.ip_version IS NOT netblock.ip_version)
                   THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE netblock.updated_at END
    WHERE (excluded.ip_version IS NOT netblock.ip_version)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM netblock WHERE netblock_cidr=:netblock_cidr LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('netblock') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='netblock' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :netblock_cidr, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:netblock_cidr LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'netblock',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// ORGANIZATION ----------------------------------------------------------------
// Params: :unique_id, :legal_name, :org_name, :active, :jurisdiction, :founding_date, :registration_id, :attrs
const tmplUpsertOrganization = `
WITH
  row_try AS (
    INSERT INTO organization(unique_id, legal_name, org_name, active, jurisdiction, founding_date, registration_id)
    VALUES (:unique_id, :legal_name, :org_name, :active, :jurisdiction, :founding_date, :registration_id)
    ON CONFLICT(unique_id) DO UPDATE SET
      legal_name      = COALESCE(excluded.legal_name,      organization.legal_name),
      org_name        = COALESCE(excluded.org_name,        organization.org_name),
      active          = COALESCE(excluded.active,          organization.active),
      jurisdiction    = COALESCE(excluded.jurisdiction,    organization.jurisdiction),
      founding_date   = COALESCE(excluded.founding_date,   organization.founding_date),
      registration_id = COALESCE(excluded.registration_id, organization.registration_id),
      updated_at      = CASE WHEN
        (excluded.legal_name      IS NOT organization.legal_name) OR
        (excluded.org_name        IS NOT organization.org_name) OR
        (excluded.active          IS NOT organization.active) OR
        (excluded.jurisdiction    IS NOT organization.jurisdiction) OR
        (excluded.founding_date   IS NOT organization.founding_date) OR
        (excluded.registration_id IS NOT organization.registration_id)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE organization.updated_at END
    WHERE (excluded.legal_name      IS NOT organization.legal_name) OR
          (excluded.org_name        IS NOT organization.org_name) OR
          (excluded.active          IS NOT organization.active) OR
          (excluded.jurisdiction    IS NOT organization.jurisdiction) OR
          (excluded.founding_date   IS NOT organization.founding_date) OR
          (excluded.registration_id IS NOT organization.registration_id)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM organization WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('organization') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='organization' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), COALESCE(:legal_name,:unique_id), coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=COALESCE(:legal_name,:unique_id) LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'organization',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// PERSON ---------------------------------------------------------------------
// Params: :unique_id, :full_name, :first_name, :family_name, :middle_name, :attrs
const tmplUpsertPerson = `
WITH
  row_try AS (
    INSERT INTO person(unique_id, full_name, first_name, family_name, middle_name)
    VALUES (:unique_id, :full_name, :first_name, :family_name, :middle_name)
    ON CONFLICT(unique_id) DO UPDATE SET
      full_name   = COALESCE(excluded.full_name,   person.full_name),
      first_name  = COALESCE(excluded.first_name,  person.first_name),
      family_name = COALESCE(excluded.family_name, person.family_name),
      middle_name = COALESCE(excluded.middle_name, person.middle_name),
      updated_at  = CASE WHEN
        (excluded.full_name   IS NOT person.full_name) OR
        (excluded.first_name  IS NOT person.first_name) OR
        (excluded.family_name IS NOT person.family_name) OR
        (excluded.middle_name IS NOT person.middle_name)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE person.updated_at END
    WHERE (excluded.full_name   IS NOT person.full_name) OR
          (excluded.first_name  IS NOT person.first_name) OR
          (excluded.family_name IS NOT person.family_name) OR
          (excluded.middle_name IS NOT person.middle_name)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM person WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('person') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='person' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), COALESCE(:full_name,:unique_id), coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=COALESCE(:full_name,:unique_id) LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'person',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// PHONE ----------------------------------------------------------------------
// Params: :raw_number, :e164, :number_type, :country_code, :country_abbrev, :attrs
const tmplUpsertPhone = `
WITH
  row_try AS (
    INSERT INTO phone(raw_number, e164, number_type, country_code, country_abbrev)
    VALUES (:raw_number, :e164, :number_type, :country_code, :country_abbrev)
    ON CONFLICT(e164) DO UPDATE SET
      raw_number     = COALESCE(excluded.raw_number,     phone.raw_number),
      number_type    = COALESCE(excluded.number_type,    phone.number_type),
      country_code   = COALESCE(excluded.country_code,   phone.country_code),
      country_abbrev = COALESCE(excluded.country_abbrev, phone.country_abbrev),
      updated_at     = CASE WHEN
        (excluded.raw_number     IS NOT phone.raw_number) OR
        (excluded.number_type    IS NOT phone.number_type) OR
        (excluded.country_code   IS NOT phone.country_code) OR
        (excluded.country_abbrev IS NOT phone.country_abbrev)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE phone.updated_at END
    WHERE (excluded.raw_number     IS NOT phone.raw_number) OR
          (excluded.number_type    IS NOT phone.number_type) OR
          (excluded.country_code   IS NOT phone.country_code) OR
          (excluded.country_abbrev IS NOT phone.country_abbrev)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM phone WHERE e164=:e164 LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('phone') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='phone' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :e164, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:e164 LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'phone',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// PRODUCT --------------------------------------------------------------------
// Params: :unique_id, :product_name, :product_type, :category, :product_description, :country_of_origin, :attrs
const tmplUpsertProduct = `
WITH
  row_try AS (
    INSERT INTO product(unique_id, product_name, product_type, category, product_description, country_of_origin)
    VALUES (:unique_id, :product_name, :product_type, :category, :product_description, :country_of_origin)
    ON CONFLICT(unique_id) DO UPDATE SET
      product_name        = COALESCE(excluded.product_name,        product.product_name),
      product_type        = COALESCE(excluded.product_type,        product.product_type),
      category            = COALESCE(excluded.category,            product.category),
      product_description = COALESCE(excluded.product_description, product.product_description),
      country_of_origin   = COALESCE(excluded.country_of_origin,   product.country_of_origin),
      updated_at          = CASE WHEN
        (excluded.product_name        IS NOT product.product_name) OR
        (excluded.product_type        IS NOT product.product_type) OR
        (excluded.category            IS NOT product.category) OR
        (excluded.product_description IS NOT product.product_description) OR
        (excluded.country_of_origin   IS NOT product.country_of_origin)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE product.updated_at END
    WHERE (excluded.product_name        IS NOT product.product_name) OR
          (excluded.product_type        IS NOT product.product_type) OR
          (excluded.category            IS NOT product.category) OR
          (excluded.product_description IS NOT product.product_description) OR
          (excluded.country_of_origin   IS NOT product.country_of_origin)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM product WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('product') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='product' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), COALESCE(:product_name,:unique_id), coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=COALESCE(:product_name,:unique_id) LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'product',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// PRODUCTRELEASE -------------------------------------------------------------
// Params: :release_name, :release_date, :attrs
const tmplUpsertProductRelease = `
WITH
  row_try AS (
    INSERT INTO productrelease(release_name, release_date)
    VALUES (:release_name, :release_date)
    ON CONFLICT(release_name) DO UPDATE SET
      release_date = COALESCE(excluded.release_date, productrelease.release_date),
      updated_at   = CASE WHEN (excluded.release_date IS NOT productrelease.release_date)
                     THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE productrelease.updated_at END
    WHERE (excluded.release_date IS NOT productrelease.release_date)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM productrelease WHERE release_name=:release_name LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('productrelease') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='productrelease' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :release_name, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:release_name LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'productrelease',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// SERVICE --------------------------------------------------------------------
// Params: :unique_id, :service_type, :output_data, :output_length, :attributes, :attrs
const tmplUpsertService = `
WITH
  row_try AS (
    INSERT INTO service(unique_id, service_type, output_data, output_length, attributes)
    VALUES (:unique_id, :service_type, :output_data, :output_length, :attributes)
    ON CONFLICT(unique_id) DO UPDATE SET
      service_type = COALESCE(excluded.service_type, service.service_type),
      output_data  = COALESCE(excluded.output_data,  service.output_data),
      output_length= COALESCE(excluded.output_length,service.output_length),
      attributes   = COALESCE(excluded.attributes,   service.attributes),
      updated_at   = CASE WHEN
        (excluded.service_type IS NOT service.service_type) OR
        (excluded.output_data  IS NOT service.output_data)  OR
        (excluded.output_length IS NOT service.output_length) OR
        (excluded.attributes   IS NOT service.attributes)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE service.updated_at END
    WHERE (excluded.service_type IS NOT service.service_type) OR
          (excluded.output_data  IS NOT service.output_data)  OR
          (excluded.output_length IS NOT service.output_length) OR
          (excluded.attributes   IS NOT service.attributes)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM service WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('service') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='service' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :unique_id, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:unique_id LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'service',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// TLSCERTIFICATE -------------------------------------------------------------
// Params: :serial_number, :subject_common_name, :is_ca, :tls_version, :key_usage, :ext_key_usage,
//
//	:not_before, :not_after, :subject_key_id, :authority_key_id, :issuer_common_name,
//	:signature_algorithm, :public_key_algorithm, :crl_distribution_points, :attrs
const tmplUpsertTLSCertificate = `
WITH
  row_try AS (
    INSERT INTO tlscertificate(
      serial_number, subject_common_name, is_ca, tls_version, key_usage, ext_key_usage,
      not_before, not_after, subject_key_id, authority_key_id, issuer_common_name,
      signature_algorithm, public_key_algorithm, crl_distribution_points
    ) VALUES (
      :serial_number, :subject_common_name, :is_ca, :tls_version, :key_usage, :ext_key_usage,
      :not_before, :not_after, :subject_key_id, :authority_key_id, :issuer_common_name,
      :signature_algorithm, :public_key_algorithm, :crl_distribution_points
    )
    ON CONFLICT(serial_number) DO UPDATE SET
      subject_common_name   = COALESCE(excluded.subject_common_name,   tlscertificate.subject_common_name),
      is_ca                 = COALESCE(excluded.is_ca,                 tlscertificate.is_ca),
      tls_version           = COALESCE(excluded.tls_version,           tlscertificate.tls_version),
      key_usage             = COALESCE(excluded.key_usage,             tlscertificate.key_usage),
      ext_key_usage         = COALESCE(excluded.ext_key_usage,         tlscertificate.ext_key_usage),
      not_before            = COALESCE(excluded.not_before,            tlscertificate.not_before),
      not_after             = COALESCE(excluded.not_after,             tlscertificate.not_after),
      subject_key_id        = COALESCE(excluded.subject_key_id,        tlscertificate.subject_key_id),
      authority_key_id      = COALESCE(excluded.authority_key_id,      tlscertificate.authority_key_id),
      issuer_common_name    = COALESCE(excluded.issuer_common_name,    tlscertificate.issuer_common_name),
      signature_algorithm   = COALESCE(excluded.signature_algorithm,   tlscertificate.signature_algorithm),
      public_key_algorithm  = COALESCE(excluded.public_key_algorithm,  tlscertificate.public_key_algorithm),
      crl_distribution_points=COALESCE(excluded.crl_distribution_points,tlscertificate.crl_distribution_points),
      updated_at            = CASE WHEN
        (excluded.subject_common_name IS NOT tlscertificate.subject_common_name) OR
        (excluded.is_ca               IS NOT tlscertificate.is_ca) OR
        (excluded.tls_version         IS NOT tlscertificate.tls_version) OR
        (excluded.key_usage           IS NOT tlscertificate.key_usage) OR
        (excluded.ext_key_usage       IS NOT tlscertificate.ext_key_usage) OR
        (excluded.not_before          IS NOT tlscertificate.not_before) OR
        (excluded.not_after           IS NOT tlscertificate.not_after) OR
        (excluded.subject_key_id      IS NOT tlscertificate.subject_key_id) OR
        (excluded.authority_key_id    IS NOT tlscertificate.authority_key_id) OR
        (excluded.issuer_common_name  IS NOT tlscertificate.issuer_common_name) OR
        (excluded.signature_algorithm IS NOT tlscertificate.signature_algorithm) OR
        (excluded.public_key_algorithm IS NOT tlscertificate.public_key_algorithm) OR
        (excluded.crl_distribution_points IS NOT tlscertificate.crl_distribution_points)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE tlscertificate.updated_at END
    WHERE (excluded.subject_common_name IS NOT tlscertificate.subject_common_name) OR
          (excluded.is_ca               IS NOT tlscertificate.is_ca) OR
          (excluded.tls_version         IS NOT tlscertificate.tls_version) OR
          (excluded.key_usage           IS NOT tlscertificate.key_usage) OR
          (excluded.ext_key_usage       IS NOT tlscertificate.ext_key_usage) OR
          (excluded.not_before          IS NOT tlscertificate.not_before) OR
          (excluded.not_after           IS NOT tlscertificate.not_after) OR
          (excluded.subject_key_id      IS NOT tlscertificate.subject_key_id) OR
          (excluded.authority_key_id    IS NOT tlscertificate.authority_key_id) OR
          (excluded.issuer_common_name  IS NOT tlscertificate.issuer_common_name) OR
          (excluded.signature_algorithm IS NOT tlscertificate.signature_algorithm) OR
          (excluded.public_key_algorithm IS NOT tlscertificate.public_key_algorithm) OR
          (excluded.crl_distribution_points IS NOT tlscertificate.crl_distribution_points)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM tlscertificate WHERE serial_number=:serial_number LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('tlscertificate') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='tlscertificate' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :serial_number, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:serial_number LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'tlscertificate',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

// URL ------------------------------------------------------------------------
// Params: :raw_url, :host, :url_path, :port, :scheme, :attrs
const tmplUpsertURL = `
WITH
  row_try AS (
    INSERT INTO url(raw_url, host, url_path, port, scheme)
    VALUES (:raw_url, :host, :url_path, :port, :scheme)
    ON CONFLICT(raw_url) DO UPDATE SET
      host       = COALESCE(excluded.host,       url.host),
      url_path   = COALESCE(excluded.url_path,   url.url_path),
      port       = COALESCE(excluded.port,       url.port),
      scheme     = COALESCE(excluded.scheme,     url.scheme),
      updated_at = CASE WHEN
        (excluded.host     IS NOT url.host) OR
        (excluded.url_path IS NOT url.url_path) OR
        (excluded.port     IS NOT url.port) OR
        (excluded.scheme   IS NOT url.scheme)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE url.updated_at END
    WHERE (excluded.host     IS NOT url.host) OR
          (excluded.url_path IS NOT url.url_path) OR
          (excluded.port     IS NOT url.port) OR
          (excluded.scheme   IS NOT url.scheme)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM url WHERE raw_url = :raw_url LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('url')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (
    SELECT id FROM ensure_type
    UNION ALL SELECT id FROM entity_type_lu WHERE name='url' LIMIT 1
  ),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :raw_url, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}'))
        ELSE entities.attrs
      END,
      updated_at = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (
    SELECT entity_id FROM ent_ins
    UNION ALL
    SELECT entity_id FROM entities
    WHERE type_id = (SELECT id FROM type_id) AND display_value = :raw_url
    LIMIT 1
  ),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id), 'url', (SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name, row_id) DO UPDATE SET
      entity_id  = excluded.entity_id,
      updated_at = strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

// ============================================================================
// Edge + Tags
// ============================================================================

// ENSURE EDGE (returns edge_id) ----------------------------------------------
// Params: :etype_name, :from_entity_id, :to_entity_id, :content(JSON)
const tmplEnsureEdge = `
WITH
  ensure_etype AS (
    INSERT INTO edge_type_lu(name) VALUES (:etype_name)
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  etype_id AS (
    SELECT id FROM ensure_etype
    UNION ALL SELECT id FROM edge_type_lu WHERE name=:etype_name LIMIT 1
  ),
  edge_try AS (
    INSERT INTO edges(etype_id, from_entity_id, to_entity_id, content)
    SELECT (SELECT id FROM etype_id), :from_entity_id, :to_entity_id, coalesce(:content,'{}')
    ON CONFLICT(etype_id, from_entity_id, to_entity_id) DO UPDATE SET
      content = CASE
        WHEN json_patch(edges.content, coalesce(excluded.content,'{}')) IS NOT edges.content
        THEN json_patch(edges.content, coalesce(excluded.content,'{}'))
        ELSE edges.content
      END,
      updated_at = CASE
        WHEN json_patch(edges.content, coalesce(excluded.content,'{}')) IS NOT edges.content
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE edges.updated_at END
    WHERE json_patch(edges.content, coalesce(excluded.content,'{}')) IS NOT edges.content
    RETURNING edge_id
  )
SELECT edge_id FROM edge_try
UNION ALL
SELECT edge_id FROM edges
WHERE etype_id = (SELECT id FROM etype_id)
  AND from_entity_id = :from_entity_id
  AND to_entity_id = :to_entity_id
LIMIT 1;`

// UPSERT TAG DICTIONARY (returns tag_id) -------------------------------------
// Params: :namespace, :name, :value, :meta(JSON)
const tmplUpsertTag = `
WITH
  t AS (
    INSERT INTO tags(namespace, name, value, meta)
    VALUES (coalesce(:namespace,'default'), :name, :value, coalesce(:meta,'{}'))
    ON CONFLICT(namespace, name, coalesce(value,'∅')) DO UPDATE SET
      meta = CASE
        WHEN json_patch(tags.meta, coalesce(excluded.meta,'{}')) IS NOT tags.meta
        THEN json_patch(tags.meta, coalesce(excluded.meta,'{}'))
        ELSE tags.meta
      END,
      updated_at = CASE
        WHEN json_patch(tags.meta, coalesce(excluded.meta,'{}')) IS NOT tags.meta
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE tags.updated_at END
    WHERE json_patch(tags.meta, coalesce(excluded.meta,'{}')) IS NOT tags.meta
    RETURNING tag_id
  )
SELECT tag_id FROM t
UNION ALL
SELECT tag_id FROM tags
WHERE namespace = coalesce(:namespace,'default')
  AND name = :name
  AND coalesce(value,'∅') = coalesce(:value,'∅')
LIMIT 1;`

// TAG ENTITY (returns mapping id) --------------------------------------------
// Params: :entity_id, :namespace, :name, :value, :details(JSON)
const tmplTagEntity = `
WITH
  tid AS (
    WITH t AS (
      INSERT INTO tags(namespace, name, value, meta)
      VALUES (coalesce(:namespace,'default'), :name, :value, '{}')
      ON CONFLICT(namespace, name, coalesce(value,'∅')) DO NOTHING
      RETURNING tag_id
    )
    SELECT tag_id FROM t
    UNION ALL
    SELECT tag_id FROM tags
    WHERE namespace = coalesce(:namespace,'default')
      AND name = :name
      AND coalesce(value,'∅') = coalesce(:value,'∅')
    LIMIT 1
  ),
  map AS (
    INSERT INTO entity_tag_map(entity_id, tag_id, details)
    SELECT :entity_id, (SELECT tag_id FROM tid), coalesce(:details,'{}')
    ON CONFLICT(entity_id, tag_id) DO UPDATE SET
      details = CASE
        WHEN json_patch(entity_tag_map.details, coalesce(excluded.details,'{}')) IS NOT entity_tag_map.details
        THEN json_patch(entity_tag_map.details, coalesce(excluded.details,'{}'))
        ELSE entity_tag_map.details
      END,
      updated_at = CASE
        WHEN json_patch(entity_tag_map.details, coalesce(excluded.details,'{}')) IS NOT entity_tag_map.details
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entity_tag_map.updated_at END
    WHERE json_patch(entity_tag_map.details, coalesce(excluded.details,'{}')) IS NOT entity_tag_map.details
    RETURNING id
  )
SELECT id FROM map
UNION ALL
SELECT id FROM entity_tag_map WHERE entity_id = :entity_id AND tag_id = (SELECT tag_id FROM tid)
LIMIT 1;`

// TAG EDGE (returns mapping id) ----------------------------------------------
// Params: :edge_id, :namespace, :name, :value, :details(JSON)
const tmplTagEdge = `
WITH
  tid AS (
    WITH t AS (
      INSERT INTO tags(namespace, name, value, meta)
      VALUES (coalesce(:namespace,'default'), :name, :value, '{}')
      ON CONFLICT(namespace, name, coalesce(value,'∅')) DO NOTHING
      RETURNING tag_id
    )
    SELECT tag_id FROM t
    UNION ALL
    SELECT tag_id FROM tags
    WHERE namespace = coalesce(:namespace,'default')
      AND name = :name
      AND coalesce(value,'∅') = coalesce(:value,'∅')
    LIMIT 1
  ),
  map AS (
    INSERT INTO edge_tag_map(edge_id, tag_id, details)
    SELECT :edge_id, (SELECT tag_id FROM tid), coalesce(:details,'{}')
    ON CONFLICT(edge_id, tag_id) DO UPDATE SET
      details = CASE
        WHEN json_patch(edge_tag_map.details, coalesce(excluded.details,'{}')) IS NOT edge_tag_map.details
        THEN json_patch(edge_tag_map.details, coalesce(excluded.details,'{}'))
        ELSE edge_tag_map.details
      END,
      updated_at = CASE
        WHEN json_patch(edge_tag_map.details, coalesce(excluded.details,'{}')) IS NOT edge_tag_map.details
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE edge_tag_map.updated_at END
    WHERE json_patch(edge_tag_map.details, coalesce(excluded.details,'{}')) IS NOT edge_tag_map.details
    RETURNING id
  )
SELECT id FROM map
UNION ALL
SELECT id FROM edge_tag_map WHERE edge_id = :edge_id AND tag_id = (SELECT tag_id FROM tid)
LIMIT 1;`
