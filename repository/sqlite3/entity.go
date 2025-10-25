// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Entity models a row in `entities` plus its inlined concrete Asset.
// Attrs is raw JSON from entities.attrs (may be nil/"{}").
type Entity struct {
	EntityID     int64           `json:"entity_id"`
	Type         string          `json:"type"`          // entity_type_lu.name
	DisplayValue string          `json:"display_value"` // entities.display_value (normalized for some types)
	Attrs        json.RawMessage `json:"attrs"`         // entities.attrs
	Asset        any             `json:"asset"`         // concrete asset struct
}

func (r *sqliteRepository) CreateEntity(ctx context.Context, entity *types.Entity) (*types.Entity, error) {
}

func (r *sqliteRepository) CreateAsset(ctx context.Context, asset oam.Asset) (*types.Entity, error) {
}

func (r *sqliteRepository) FindEntityById(ctx context.Context, id string) (*types.Entity, error) {
	entityId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return nil, err
	}
	return r.queries.FindEntityByID(ctx, int64(entityId))
}

func (r *sqliteRepository) FindEntitiesByContent(ctx context.Context, etype string, since time.Time, filters ContentFilters) ([]*types.Entity, error) {
	ents, err := r.queries.FindByContent(ctx, etype, filters, 0)
	if err != nil {
		return nil, err
	}

	if since.IsZero() {
		return ents, nil
	}

	var filtered []*types.Entity
	for _, e := range ents {
		if e.LastSeen.After(since) {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == 0 {
		return nil, errors.New("zero entities found")
	}
	return filtered, nil
}

func (r *sqliteRepository) FindOneEntityByContent(ctx context.Context, etype string, since time.Time, filters ContentFilters) (*types.Entity, error) {
	ent, err := r.queries.FindOneByContent(ctx, etype, filters)
	if err != nil {
		return nil, err
	}
	if ent.LastSeen.Before(since) {
		return nil, errors.New("entity not found")
	}
	return ent, nil
}

func (r *sqliteRepository) FindEntitiesByType(ctx context.Context, atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	ents, err := r.queries.FindEntitiesByType(ctx, string(atype), 0)
	if err != nil {
		return nil, err
	}
	if since.IsZero() {
		return ents, nil
	}

	var filtered []*types.Entity
	for _, e := range ents {
		if e.LastSeen.After(since) {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == 0 {
		return nil, errors.New("zero entities found")
	}
	return filtered, nil
}

func (r *sqliteRepository) DeleteEntity(ctx context.Context, id string) error {
	entityId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}
	return r.queries.DeleteEntityByID(ctx, int64(entityId), true)
}

// ============================== Queries Implementation ==============================

// FindEntityByID returns the Entity (with Asset populated) for a given entity_id.
func (r *Queries) FindEntityByID(ctx context.Context, entityID int64) (*types.Entity, error) {
	e, err := r.loadEntityCore(ctx, entityID)
	if err != nil {
		return nil, err
	}
	return r.fetchCompleteRepoEntity(ctx, e)
}

// FindByAssetPK returns Entity/Asset for a specific table primary key id.
func (r *Queries) FindByAssetPK(ctx context.Context, tableName string, rowID int64) (*types.Entity, error) {
	table := normalizeTable(tableName)
	var eid int64
	if err := r.stmtEntityIDByAssetPK.QueryRowContext(ctx, table, rowID).Scan(&eid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no entity for %s(%d)", table, rowID)
		}
		return nil, err
	}
	return r.FindEntityByID(ctx, eid)
}

// FindByTypeAndValue returns Entity/Asset by asset type and its display value.
// For types requiring normalization (fqdn/domainrecord), normalization is applied.
func (r *Queries) FindByTypeAndValue(ctx context.Context, assetType, value string) (*types.Entity, error) {
	t := normalizeType(assetType)
	v := normalizeValueForType(t, value)

	var eid int64
	if err := r.stmtEntityIDByTypeValue.QueryRowContext(ctx, t, v).Scan(&eid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no entity for type=%s value=%q", t, value)
		}
		return nil, err
	}
	return r.FindEntityByID(ctx, eid)
}

// FindByContent builds the SQL WHERE from a registry of allowed columns per
// asset type, and returns Entity+Asset. Supports multiple matches.

type ContentFilters map[string]any

// FindOneByContent returns exactly one (first by updated_at desc)
func (r *Queries) FindOneByContent(ctx context.Context, assetType string, filters ContentFilters) (*types.Entity, error) {
	ents, err := r.FindByContent(ctx, assetType, filters, 1)
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		return nil, sql.ErrNoRows
	}
	return ents[0], nil
}

// FindByContent finds entities for asset type with given filters (on the asset table).
// limit <= 0 => no explicit LIMIT.
func (r *Queries) FindByContent(ctx context.Context, assetType string, filters ContentFilters, limit int) ([]*types.Entity, error) {
	table := normalizeType(assetType)
	if table == "" {
		return nil, fmt.Errorf("unknown asset type %q", assetType)
	}

	// Normalize/validate filters against registry for that table.
	reg, ok := contentRegistry[table]
	if !ok {
		return nil, fmt.Errorf("no content registry for table %q", table)
	}
	where, args, err := buildWhere(table, reg, filters)
	if err != nil {
		return nil, err
	}

	// Query entity ids via entity_ref join to the concrete asset table.
	sb := strings.Builder{}
	sb.WriteString(`
SELECT e.entity_id
FROM entities e
JOIN entity_type_lu t ON t.id = e.type_id AND t.name = ? 
JOIN entity_ref r ON r.entity_id = e.entity_id AND r.table_name = ? 
JOIN ` + table + ` a ON a.id = r.row_id
`)
	args = append([]any{table, table}, args...) // prepend type/table to args
	if where != "" {
		sb.WriteString("WHERE " + where + "\n")
	}
	sb.WriteString("ORDER BY e.updated_at DESC")
	if limit > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
	}

	q := sb.String()
	key := "q.findByContent." + table + "." + strings.Join(reg.keys, ",") // stable key per table/registry
	st, err := r.getOrPrepare(ctx, key, q)
	if err != nil {
		return nil, err
	}

	rows, err := st.QueryContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*types.Entity
	for rows.Next() {
		var eid int64
		if err := rows.Scan(&eid); err != nil {
			return nil, err
		}
		ent, err := r.FindEntityByID(ctx, eid)
		if err != nil {
			return nil, err
		}
		out = append(out, ent)
	}
	return out, rows.Err()
}

// FindEntitiesByType returns up to `limit` Entities of the given asset type,
// ordered by most recently updated (DESC). Each Entity has its concrete Asset populated.
//
// If limit <= 0, it returns all (be careful on large datasets).
func (r *Queries) FindEntitiesByType(ctx context.Context, assetType string, limit int) ([]*types.Entity, error) {
	t := normalizeType(assetType)

	// Build SQL (parameterized LIMIT only if > 0, to keep a stable prepared key)
	base := `
SELECT e.entity_id, e.display_value, e.attrs
FROM entities e
JOIN entity_type_lu t ON t.id = e.type_id AND t.name = ?
ORDER BY e.updated_at DESC, e.entity_id DESC`
	key := "q.entities.byType.base"
	q := base
	var st *sql.Stmt
	var err error

	if limit > 0 {
		q = base + " LIMIT ?"
		key = "q.entities.byType.base.limit"
	}
	if st, err = r.getOrPrepare(ctx, key, q); err != nil {
		return nil, err
	}

	var rows *sql.Rows
	if limit > 0 {
		rows, err = st.QueryContext(ctx, t, limit)
	} else {
		rows, err = st.QueryContext(ctx, t)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*types.Entity, 0, max(0, limit))
	for rows.Next() {
		var eid int64
		var disp string
		var raw *string
		if err := rows.Scan(&eid, &disp, &raw); err != nil {
			return nil, err
		}
		// Hydrate via existing logic (populates Type + Asset)
		ent, err := r.FindEntityByID(ctx, eid)
		if err != nil {
			return nil, err
		}
		out = append(out, ent)
	}
	return out, rows.Err()
}

// FindEntitiesByTypePaged is an optional cursor-based paginator.
// Pass since to only return entities updated_at >= since.
// Pass afterEntityID to continue after a prior page (stable on updated_at,entity_id).
// Set limit <= 0 for no explicit cap.
func (r *Queries) FindEntitiesByTypePaged(ctx context.Context, assetType string, since time.Time, afterEntityID int64, limit int) ([]*types.Entity, error) {
	t := normalizeType(assetType)

	sb := strings.Builder{}
	sb.WriteString(`
SELECT e.entity_id, e.display_value, e.attrs
FROM entities e
JOIN entity_type_lu t ON t.id = e.type_id AND t.name = ?`)
	args := []any{t}

	if !since.IsZero() || afterEntityID > 0 {
		sb.WriteString(" WHERE 1=1")
		if !since.IsZero() {
			// Use the same format parseTS expects on reads
			args = append(args, since.UTC().Format("2006-01-02 15:04:05.000"))
			sb.WriteString(" AND e.updated_at >= ?")
		}
		if afterEntityID > 0 {
			// Continue *after* a known entity_id (useful when updated_at ties are common)
			args = append(args, afterEntityID)
			sb.WriteString(" AND e.entity_id < ?")
		}
	}
	sb.WriteString(" ORDER BY e.updated_at DESC, e.entity_id DESC")
	if limit > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT %d", limit)) // LIMIT can be bound, but we keep key stability here
	}

	q := sb.String()
	key := "q.entities.byType.paged:" + boolKey(!since.IsZero()) + ":" + boolKey(afterEntityID > 0) + ":" + limitKey(limit)
	st, err := r.getOrPrepare(ctx, key, q)
	if err != nil {
		return nil, err
	}

	rows, err := st.QueryContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*types.Entity
	for rows.Next() {
		var eid int64
		var disp string
		var raw *string
		if err := rows.Scan(&eid, &disp, &raw); err != nil {
			return nil, err
		}
		ent, err := r.FindEntityByID(ctx, eid)
		if err != nil {
			return nil, err
		}
		out = append(out, ent)
	}
	return out, rows.Err()
}

// --- tiny helpers used above ---
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func boolKey(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
func limitKey(n int) string {
	if n <= 0 {
		return "all"
	}
	return fmt.Sprintf("%d", n)
}

// DeleteEntityByID deletes a single entity and (via FK CASCADE) its incident edges
// and tag mappings. It leaves the concrete asset row intact by default; if you also
// want to remove the asset row, set alsoDeleteAsset=true.
func (r *Queries) DeleteEntityByID(ctx context.Context, entityID int64, alsoDeleteAsset bool) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Optionally remove the concrete asset row (requires looking up its table + row_id)
	if alsoDeleteAsset {
		const keySel = "del.entity.refRow"
		const qSel = `SELECT table_name, row_id FROM entity_ref WHERE entity_id = ?`
		stSel, err := r.getOrPrepare(ctx, keySel, qSel)
		if err != nil {
			return err
		}
		rows, err := tx.Stmt(stSel).QueryContext(ctx, entityID)
		if err != nil {
			return err
		}
		type ref struct {
			table string
			rowID int64
		}
		var refs []ref
		for rows.Next() {
			var t string
			var id int64
			if err := rows.Scan(&t, &id); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, ref{table: t, rowID: id})
		}
		rows.Close()

		for _, rf := range refs {
			tbl := validateAssetTable(rf.table)
			if tbl == "" {
				// unknown table: skip instead of failing the whole deletion
				continue
			}
			delQ := fmt.Sprintf(`DELETE FROM %s WHERE id = ?`, tbl)
			key := "del.asset." + tbl
			st, err := r.getOrPrepare(ctx, key, delQ)
			if err != nil {
				return err
			}
			if _, err := tx.Stmt(st).ExecContext(ctx, rf.rowID); err != nil {
				return err
			}
		}
	}

	// Delete the entity (FKs should take care of edges, entity_ref, tag maps if schema has CASCADE)
	const keyDel = "del.entity.byID"
	const qDel = `DELETE FROM entities WHERE entity_id = ?`
	stDel, err := r.getOrPrepare(ctx, keyDel, qDel)
	if err != nil {
		return err
	}
	res, err := tx.Stmt(stDel).ExecContext(ctx, entityID)
	if err != nil {
		return err
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// DeleteByAssetPK deletes by concrete asset primary key (table + row id).
// It removes the asset row, the entity_ref mapping, and the entity (cascading incident data).
func (r *Queries) DeleteByAssetPK(ctx context.Context, tableName string, rowID int64) error {
	tbl := validateAssetTable(tableName)
	if tbl == "" {
		return fmt.Errorf("unknown/unsupported asset table %q", tableName)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Resolve entity_id
	const keySel = "del.entityID.byAssetPK"
	const qSel = `SELECT entity_id FROM entity_ref WHERE table_name = ? AND row_id = ? LIMIT 1`
	stSel, err := r.getOrPrepare(ctx, keySel, qSel)
	if err != nil {
		return err
	}
	var eid int64
	if err := tx.Stmt(stSel).QueryRowContext(ctx, tbl, rowID).Scan(&eid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// If no mapping exists, just delete the asset row
			delQ := fmt.Sprintf(`DELETE FROM %s WHERE id = ?`, tbl)
			key := "del.asset.only." + tbl
			st, e2 := r.getOrPrepare(ctx, key, delQ)
			if e2 != nil {
				return e2
			}
			if _, e2 = tx.Stmt(st).ExecContext(ctx, rowID); e2 != nil {
				return e2
			}
			return tx.Commit()
		}
		return err
	}

	// Delete asset row first (to avoid leaving an orphan if entity delete somehow fails)
	delQ := fmt.Sprintf(`DELETE FROM %s WHERE id = ?`, tbl)
	keyDelAsset := "del.asset." + tbl
	stDelAsset, err := r.getOrPrepare(ctx, keyDelAsset, delQ)
	if err != nil {
		return err
	}
	if _, err := tx.Stmt(stDelAsset).ExecContext(ctx, rowID); err != nil {
		return err
	}

	// Delete the entity (will cascade to entity_ref, edges, and tag maps if CASCADE is enabled)
	const keyDelEnt = "del.entity.byID"
	const qDelEnt = `DELETE FROM entities WHERE entity_id = ?`
	stDelEnt, err := r.getOrPrepare(ctx, keyDelEnt, qDelEnt)
	if err != nil {
		return err
	}
	if _, err := tx.Stmt(stDelEnt).ExecContext(ctx, eid); err != nil {
		return err
	}

	return tx.Commit()
}

// ============================== Registry ==============================

// regEntry describes what content keys are allowed for each table and how
// they map to columns + normalization.
type regEntry struct {
	// keys is a stable slice of allowed external filter keys (e.g., "fqdn", "domain", "ip_address")
	keys []string
	// colMap maps external key -> actual column expression (e.g., "fqdn" -> "lower(a.fqdn)")
	colMap map[string]string
}

// contentRegistry: per-table filters you can search on.
// Feel free to expand with more columns if needed.
var contentRegistry = map[string]regEntry{
	"fqdn": {
		keys: []string{"fqdn"},
		colMap: map[string]string{
			"fqdn": "lower(a.fqdn)",
		},
	},
	"ipaddress": {
		keys: []string{"ip_address", "ip_version"},
		colMap: map[string]string{
			"ip_address": "a.ip_address",
			"ip_version": "a.ip_version",
		},
	},
	"domainrecord": {
		keys: []string{"domain", "record_name", "extension", "punycode"},
		colMap: map[string]string{
			"domain":      "lower(a.domain)",
			"record_name": "lower(a.record_name)",
			"extension":   "a.extension",
			"punycode":    "a.punycode",
		},
	},
	"url": {
		keys: []string{"raw_url", "host", "url_path", "port", "scheme"},
		colMap: map[string]string{
			"raw_url":  "a.raw_url",
			"host":     "a.host",
			"url_path": "a.url_path",
			"port":     "a.port",
			"scheme":   "a.scheme",
		},
	},
	"organization": {
		keys: []string{"unique_id", "legal_name", "org_name"},
		colMap: map[string]string{
			"unique_id":  "a.unique_id",
			"legal_name": "a.legal_name",
			"org_name":   "a.org_name",
		},
	},
	"autonomoussystem": {
		keys: []string{"asn"},
		colMap: map[string]string{
			"asn": "a.asn",
		},
	},
	"autnumrecord": {
		keys: []string{"asn", "handle", "record_name"},
		colMap: map[string]string{
			"asn":         "a.asn",
			"handle":      "a.handle",
			"record_name": "a.record_name",
		},
	},
	"ipnetrecord": {
		keys: []string{"record_cidr", "handle", "ip_version", "country"},
		colMap: map[string]string{
			"record_cidr": "a.record_cidr",
			"handle":      "a.handle",
			"ip_version":  "a.ip_version",
			"country":     "a.country",
		},
	},
	"netblock": {
		keys: []string{"netblock_cidr", "ip_version"},
		colMap: map[string]string{
			"netblock_cidr": "a.netblock_cidr",
			"ip_version":    "a.ip_version",
		},
	},
	"file": {
		keys: []string{"file_url", "basename", "file_type"},
		colMap: map[string]string{
			"file_url":  "a.file_url",
			"basename":  "a.basename",
			"file_type": "a.file_type",
		},
	},
	"service": {
		keys: []string{"unique_id", "service_type"},
		colMap: map[string]string{
			"unique_id":    "a.unique_id",
			"service_type": "a.service_type",
		},
	},
	"identifier": {
		keys: []string{"unique_id", "id_type"},
		colMap: map[string]string{
			"unique_id": "a.unique_id",
			"id_type":   "a.id_type",
		},
	},
	"account": {
		keys: []string{"unique_id", "account_type", "username", "account_number"},
		colMap: map[string]string{
			"unique_id":      "a.unique_id",
			"account_type":   "a.account_type",
			"username":       "a.username",
			"account_number": "a.account_number",
		},
	},
	"fundstransfer": {
		keys: []string{"unique_id", "reference_number", "currency", "transfer_method"},
		colMap: map[string]string{
			"unique_id":        "a.unique_id",
			"reference_number": "a.reference_number",
			"currency":         "a.currency",
			"transfer_method":  "a.transfer_method",
		},
	},
	"location": {
		keys: []string{"street_address", "city", "country", "postal_code"},
		colMap: map[string]string{
			"street_address": "a.street_address",
			"city":           "a.city",
			"country":        "a.country",
			"postal_code":    "a.postal_code",
		},
	},
	"person": {
		keys: []string{"unique_id", "full_name", "first_name", "family_name"},
		colMap: map[string]string{
			"unique_id":   "a.unique_id",
			"full_name":   "a.full_name",
			"first_name":  "a.first_name",
			"family_name": "a.family_name",
		},
	},
	"phone": {
		keys: []string{"e164", "raw_number", "country_abbrev"},
		colMap: map[string]string{
			"e164":           "a.e164",
			"raw_number":     "a.raw_number",
			"country_abbrev": "a.country_abbrev",
		},
	},
	"product": {
		keys: []string{"unique_id", "product_name", "product_type", "category"},
		colMap: map[string]string{
			"unique_id":    "a.unique_id",
			"product_name": "a.product_name",
			"product_type": "a.product_type",
			"category":     "a.category",
		},
	},
	"productrelease": {
		keys: []string{"release_name"},
		colMap: map[string]string{
			"release_name": "a.release_name",
		},
	},
	"tlscertificate": {
		keys: []string{"serial_number", "subject_common_name", "issuer_common_name"},
		colMap: map[string]string{
			"serial_number":       "a.serial_number",
			"subject_common_name": "a.subject_common_name",
			"issuer_common_name":  "a.issuer_common_name",
		},
	},
}

// buildWhere validates the provided filters and builds "col = ?" AND ... with args.
// It honors case-insensitive matching for columns that already use lower() in colMap.
func buildWhere(table string, reg regEntry, filters ContentFilters) (string, []any, error) {
	if len(filters) == 0 {
		// No filters — allow full scan over that table via entity_ref (but still ordered by updated_at).
		// Usually caller should set a LIMIT in this case.
		return "", nil, nil
	}
	// Validate keys and order them stably for deterministic SQL key (cache)
	allowed := map[string]struct{}{}
	for _, k := range reg.keys {
		allowed[k] = struct{}{}
	}
	keys := slices.Sorted(maps.Keys(filters))

	parts := make([]string, 0, len(keys))
	args := make([]any, 0, len(keys))
	for _, k := range keys {
		if _, ok := allowed[k]; !ok {
			return "", nil, fmt.Errorf("unsupported filter %q for table %s (allowed: %v)", k, table, reg.keys)
		}
		col := reg.colMap[k]
		if col == "" {
			return "", nil, fmt.Errorf("no column mapping for filter %q on table %s", k, table)
		}
		// For lower(a.col) use normalized string value if possible
		val := filters[k]
		if strings.HasPrefix(col, "lower(") {
			if s, ok := val.(string); ok {
				val = strings.ToLower(s)
			}
		}
		parts = append(parts, col+" = ?")
		args = append(args, val)
	}
	return strings.Join(parts, " AND "), args, nil
}

// ============================== Asset hydration ==============================

func normalizeTable(name string) string { return strings.ToLower(strings.TrimSpace(name)) }
func normalizeType(name string) string  { return strings.ToLower(strings.TrimSpace(name)) }

// normalizeValueForType applies display_value normalization the same way
// your ingestion does (lowercase for fqdn/domainrecord; others exact).
func normalizeValueForType(t, v string) string {
	switch t {
	case "fqdn", "domainrecord":
		return strings.ToLower(v)
	default:
		return v
	}
}

// validateAssetTable ensures we only allow deletion against known asset tables.
// Returns normalized table name or "" if unsupported.
func validateAssetTable(tableName string) string {
	switch strings.ToLower(strings.TrimSpace(tableName)) {
	case "account",
		"autnumrecord",
		"autonomoussystem",
		"contactrecord",
		"domainrecord",
		"file",
		"fqdn",
		"fundstransfer",
		"identifier",
		"ipaddress",
		"ipnetrecord",
		"location",
		"netblock",
		"organization",
		"person",
		"phone",
		"product",
		"productrelease",
		"service",
		"tlscertificate",
		"url":
		return strings.ToLower(strings.TrimSpace(tableName))
	default:
		return ""
	}
}

func (r *Queries) loadEntityCore(ctx context.Context, entityID int64) (*Entity, error) {
	var e Entity
	var raw string
	if err := r.stmtEntityByID.QueryRowContext(ctx, entityID).Scan(&e.EntityID, &e.Type, &e.DisplayValue, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("entity %d not found", entityID)
		}
		return nil, err
	}
	if strings.TrimSpace(raw) != "" {
		e.Attrs = json.RawMessage(raw)
	}
	return &e, nil
}

func (r *Queries) fetchCompleteRepoEntity(ctx context.Context, e *Entity) (*types.Entity, error) {
	table := e.Type
	if table == "" {
		return nil, fmt.Errorf("no table mapping for entity type %q", e.Type)
	}
	// Resolve the row id in that concrete table via entity_ref
	var rowID int64
	if err := r.stmtRefRowByEntityTable.QueryRowContext(ctx, e.EntityID, table).Scan(&rowID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Entity exists but does not have a ref to the expected table (data drift)
			return nil, fmt.Errorf("entity %d has no %s row mapping", e.EntityID, table)
		}
		return nil, err
	}

	return r.fetchEntityAssetByTableID(ctx, e.EntityID, table, rowID)
}

// fetchEntityAssetByTableID selects the concrete asset row and scans into its struct.
// Statements are prepared lazily and cached per table name.
func (r *Queries) fetchEntityAssetByTableID(ctx context.Context, entity_id int64, table string, id int64) (*types.Entity, error) {
	switch table {
	case "account":
		return r.fetchAccountByRowID(ctx, entity_id, id)
	case "autnumrecord":
		return r.fetchAutnumRecordByRowID(ctx, entity_id, id)
	case "autonomoussystem":
		return r.fetchAutonomousSystemByRowID(ctx, entity_id, id)
	case "contactrecord":
		return r.fetchContactRecordByRowID(ctx, entity_id, id)
	case "domainrecord":
		return r.fetchDomainRecordByRowID(ctx, entity_id, id)
	case "file":
		return r.fetchFileByRowID(ctx, entity_id, id)
	case "fqdn":
		return r.fetchFQDNByRowID(ctx, entity_id, id)
	case "fundstransfer":
		return r.fetchFundsTransferByRowID(ctx, entity_id, id)
	case "identifier":
		return r.fetchIdentifierByRowID(ctx, entity_id, id)
	case "ipaddress":
		return r.fetchIPAddressByRowID(ctx, entity_id, id)
	case "ipnetrecord":
		return r.fetchIPNetRecordByRowID(ctx, entity_id, id)
	case "location":
		return r.fetchLocationByRowID(ctx, entity_id, id)
	case "netblock":
		return r.fetchNetblockByRowID(ctx, entity_id, id)
	case "organization":
		return r.fetchOrganizationByRowID(ctx, entity_id, id)
	case "person":
		return r.fetchPersonByRowID(ctx, entity_id, id)
	case "phone":
		return r.fetchPhoneByRowID(ctx, entity_id, id)
	case "product":
		return r.fetchProductByRowID(ctx, entity_id, id)
	case "productrelease":
		return r.fetchProductReleaseByRowID(ctx, entity_id, id)
	case "service":
		return r.fetchServiceByRowID(ctx, entity_id, id)
	case "tlscertificate":
		return r.fetchTLSCertificateByRowID(ctx, entity_id, id)
	case "url":
		return r.fetchURLByRowID(ctx, entity_id, id)
	}

	return nil, fmt.Errorf("unhandled table %q", table)
}
