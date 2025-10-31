// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
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

// FindEntityById implements the Repository interface.
func (r *SqliteRepository) FindEntityById(ctx context.Context, id string) (*types.Entity, error) {
	entityId, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	return r.idToEntity(ctx, entityId)
}

func (r *SqliteRepository) idToEntity(ctx context.Context, eid int64) (*types.Entity, error) {
	e, err := r.loadEntityCore(ctx, eid)
	if err != nil {
		return nil, err
	}

	return r.fetchCompleteRepoEntity(ctx, e)
}

func (r *SqliteRepository) FindEntitiesByContent(ctx context.Context, etype string, since time.Time, filters types.ContentFilters) ([]*types.Entity, error) {
	ents, err := r.findByContent(ctx, etype, filters, 0)
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

func (r *SqliteRepository) FindOneEntityByContent(ctx context.Context, etype string, since time.Time, filters types.ContentFilters) (*types.Entity, error) {
	ent, err := r.findOneByContent(ctx, etype, filters)
	if err != nil {
		return nil, err
	}
	if ent.LastSeen.Before(since) {
		return nil, errors.New("entity not found")
	}
	return ent, nil
}

func (r *SqliteRepository) FindEntitiesByType(ctx context.Context, atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	ents, err := r.findByType(ctx, string(atype), 0)
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

// findByContent builds the SQL WHERE from a registry of allowed columns per
// asset type, and returns Entity+Asset. Supports multiple matches.

// findOneByContent returns exactly one (first by updated_at desc)
func (r *SqliteRepository) findOneByContent(ctx context.Context, assetType string, filters types.ContentFilters) (*types.Entity, error) {
	ents, err := r.findByContent(ctx, assetType, filters, 1)
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		return nil, sql.ErrNoRows
	}
	return ents[0], nil
}

// findByContent finds entities for asset type with given filters (on the asset table).
// limit <= 0 => no explicit LIMIT.
func (r *SqliteRepository) findByContent(ctx context.Context, assetType string, filters types.ContentFilters, limit int) ([]*types.Entity, error) {
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
FROM entity e
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
	key := "q.findByContent." + table + "." + strings.Join(reg.keys, ".") + fmt.Sprintf("limit%d", limit)

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{
		Ctx:     ctx,
		Name:    key,
		SQLText: q,
		Args:    args,
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	var out []*types.Entity
	for result.Rows.Next() {
		var eid int64
		if err := result.Rows.Scan(&eid); err != nil {
			return nil, err
		}
		ent, err := r.idToEntity(ctx, eid)
		if err != nil {
			return nil, err
		}
		out = append(out, ent)
	}
	return out, result.Rows.Err()
}

// findByType returns up to `limit` Entities of the given asset type,
// ordered by most recently updated (DESC). Each Entity has its concrete Asset populated.
//
// If limit <= 0, it returns all (be careful on large datasets).
func (r *SqliteRepository) findByType(ctx context.Context, assetType string, limit int) ([]*types.Entity, error) {
	table := normalizeType(assetType)

	// Build SQL (parameterized LIMIT only if > 0, to keep a stable prepared key)
	base := `
SELECT e.entity_id, e.display_value, e.attrs
FROM entity e
JOIN entity_type_lu t ON t.id = e.type_id AND t.name = ?
ORDER BY e.updated_at DESC, e.entity_id DESC`
	key := "entity.by_type.base"
	q := base
	args := []any{table}

	if limit > 0 {
		q = base + " LIMIT ?"
		args = append(args, limit)
		key = "entity.by_type.base.limit"
	}

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{
		Ctx:     ctx,
		Name:    key,
		SQLText: q,
		Args:    args,
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	out := make([]*types.Entity, 0, max(0, limit))
	for result.Rows.Next() {
		var eid int64
		var disp string
		var raw *string
		if err := result.Rows.Scan(&eid, &disp, &raw); err != nil {
			return nil, err
		}
		// Hydrate via existing logic (populates Type + Asset)
		ent, err := r.idToEntity(ctx, eid)
		if err != nil {
			return nil, err
		}
		out = append(out, ent)
	}
	return out, result.Rows.Err()
}

// --- tiny helper used above ---
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
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
func buildWhere(table string, reg regEntry, filters types.ContentFilters) (string, []any, error) {
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
