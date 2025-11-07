// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// FindEntityById implements the Repository interface.
func (r *SqliteRepository) FindEntityById(ctx context.Context, id string) (*dbt.Entity, error) {
	entityId, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	return r.idToEntity(ctx, entityId)
}

func (r *SqliteRepository) idToEntity(ctx context.Context, eid int64) (*dbt.Entity, error) {
	e, err := r.loadEntityCore(ctx, eid)
	if err != nil {
		return nil, err
	}

	return r.fetchCompleteRepoEntity(ctx, e)
}

func (r *SqliteRepository) FindEntitiesByContent(ctx context.Context, etype string, since time.Time, filters dbt.ContentFilters) ([]*dbt.Entity, error) {
	ents, err := r.findByContent(ctx, etype, since, filters, 0)
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		return nil, errors.New("zero entities found")
	}
	return ents, nil
}

func (r *SqliteRepository) FindOneEntityByContent(ctx context.Context, etype string, since time.Time, filters dbt.ContentFilters) (*dbt.Entity, error) {
	ent, err := r.findOneByContent(ctx, etype, since, filters)
	if err != nil {
		return nil, err
	}
	if ent == nil {
		return nil, errors.New("entity not found")
	}
	return ent, nil
}

func (r *SqliteRepository) FindEntitiesByType(ctx context.Context, atype oam.AssetType, since time.Time) ([]*dbt.Entity, error) {
	ents, err := r.findByType(ctx, string(atype), since, 0)
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		return nil, errors.New("zero entities found")
	}
	return ents, nil
}

// findByContent builds the SQL WHERE from a registry of allowed columns per
// asset type, and returns Entity+Asset. Supports multiple matches.

// findOneByContent returns exactly one (first by updated_at desc)
func (r *SqliteRepository) findOneByContent(ctx context.Context, atype string, since time.Time, filters dbt.ContentFilters) (*dbt.Entity, error) {
	ents, err := r.findByContent(ctx, atype, since, filters, 1)
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		return nil, errors.New("zero entities found")
	}
	return ents[0], nil
}

// findByContent finds entities for asset type with given filters (on the asset table).
// limit <= 0 => no explicit LIMIT.
func (r *SqliteRepository) findByContent(ctx context.Context, atype string, since time.Time, filters dbt.ContentFilters, limit int) ([]*dbt.Entity, error) {
	table := normalizeType(atype)
	if table == "" {
		return nil, fmt.Errorf("unknown asset type %q", atype)
	}

	// Normalize/validate filters against registry for that table.
	reg, ok := contentRegistry[table]
	if !ok {
		return nil, fmt.Errorf("no content registry for table %q", table)
	}

	where, args, err := buildWhere(table, reg, since, filters)
	if err != nil {
		return nil, err
	}

	// Query entity ids via join to the concrete asset table.
	sb := strings.Builder{}
	sb.WriteString(`
SELECT e.entity_id FROM entity e
JOIN entity_type_lu t ON t.id = e.type_id AND t.name = ? 
JOIN ` + table + ` a ON a.id = e.row_id`)

	args = append([]any{table}, args...) // prepend type/table to args
	if where != "" {
		sb.WriteString(" WHERE " + where + "\n")
	}
	sb.WriteString("ORDER BY e.updated_at DESC")
	if limit > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
	}

	q := sb.String()
	key := "q.findByContent." + table + "." + where + fmt.Sprintf("limit%d", limit)

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

	var out []*dbt.Entity
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

// buildWhere validates the provided filters and builds "col = ?" AND ... with args.
// It honors case-insensitive matching for columns that already use lower() in colMap.
func buildWhere(table string, reg regEntry, since time.Time, filters dbt.ContentFilters) (string, []any, error) {
	if len(filters) == 0 {
		// No filters — allow full scan over that table via entity (but still ordered by updated_at).
		// Usually caller should set a LIMIT in this case.
		return "", nil, errors.New("no filters provided")
	}

	// Validate keys and order them stably for deterministic SQL key (cache)
	allowed := map[string]struct{}{}
	for _, k := range reg.keys {
		allowed[k] = struct{}{}
	}
	keys := slices.Sorted(maps.Keys(filters))

	parts := make([]string, 0, len(keys))
	args := make([]any, 0, len(keys))

	if !since.IsZero() {
		parts = append(parts, "a.updated_at >= ?")
		args = append(args, since.UTC())
	}

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

// findByType returns up to `limit` Entities of the given asset type,
// ordered by most recently updated (DESC). Each Entity has its concrete Asset populated.
//
// If limit <= 0, it returns all (be careful on large datasets).
func (r *SqliteRepository) findByType(ctx context.Context, atype string, since time.Time, limit int) ([]*dbt.Entity, error) {
	table := normalizeType(atype)
	// Build SQL (parameterized LIMIT only if > 0, to keep a stable prepared key)
	base := `
SELECT e.entity_id, e.natural_key, e.attrs
FROM entity e
JOIN entity_type_lu t ON t.id = e.type_id AND t.name = ?`
	key := "entity.by_type.base"
	q := base
	args := []any{table}

	if !since.IsZero() {
		key += ".since"
		q += " WHERE e.updated_at >= ?"
		args = append(args, since.UTC())
	}

	q += " ORDER BY e.updated_at DESC, e.entity_id DESC"

	if limit > 0 {
		key += fmt.Sprintf(".limit%d", limit)
		q = base + " LIMIT ?"
		args = append(args, limit)
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

	out := make([]*dbt.Entity, 0, max(0, limit))
	for result.Rows.Next() {
		var eid int64
		var disp string
		var raw string
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
	"account": {
		keys: []string{"unique_id", "account_type", "username", "account_number"},
		colMap: map[string]string{
			"unique_id":      "a.unique_id",
			"account_type":   "a.account_type",
			"username":       "a.username",
			"account_number": "a.account_number",
		},
	},
	"autnumrecord": {
		keys: []string{"number", "handle", "name", "whois_server"},
		colMap: map[string]string{
			"number":       "a.asn",
			"handle":       "a.handle",
			"name":         "a.record_name",
			"whois_server": "a.whois_server",
		},
	},
	"autonomoussystem": {
		keys: []string{"number"},
		colMap: map[string]string{
			"number": "a.asn",
		},
	},
	"contactrecord": {
		keys: []string{"discovered_at"},
		colMap: map[string]string{
			"discovered_at": "a.discovered_at",
		},
	},
	"domainrecord": {
		keys: []string{"domain", "name", "extension", "punycode", "id", "whois_server"},
		colMap: map[string]string{
			"domain":       "lower(a.domain)",
			"name":         "lower(a.record_name)",
			"extension":    "a.extension",
			"punycode":     "a.punycode",
			"id":           "a.object_id",
			"whois_server": "a.whois_server",
		},
	},
	"file": {
		keys: []string{"url", "name", "type"},
		colMap: map[string]string{
			"url":  "a.file_url",
			"name": "a.basename",
			"type": "a.file_type",
		},
	},
	"fqdn": {
		keys: []string{"name"},
		colMap: map[string]string{
			"name": "lower(a.fqdn)",
		},
	},
	"fundstransfer": {
		keys: []string{"unique_id", "amount", "reference_number", "currency", "transfer_method", "exchange_rate"},
		colMap: map[string]string{
			"unique_id":        "a.unique_id",
			"amount":           "a.amount",
			"reference_number": "a.reference_number",
			"currency":         "a.currency",
			"transfer_method":  "a.transfer_method",
			"exchange_rate":    "a.exchange_rate",
		},
	},
	"identifier": {
		keys: []string{"id", "id_type"},
		colMap: map[string]string{
			"id":      "a.unique_id",
			"id_type": "a.id_type",
		},
	},
	"ipaddress": {
		keys: []string{"address", "type"},
		colMap: map[string]string{
			"address": "a.ip_address",
			"type":    "a.ip_version",
		},
	},
	"ipnetrecord": {
		keys: []string{
			"cidr", "handle", "name", "type", "start_address",
			"end_address", "whois_server", "method", "country", "parent_handle",
		},
		colMap: map[string]string{
			"cidr":          "a.record_cidr",
			"handle":        "a.handle",
			"name":          "a.record_name",
			"type":          "a.ip_version",
			"start_address": "a.start_address",
			"end_address":   "a.end_address",
			"whois_server":  "a.whois_server",
			"method":        "a.method",
			"country":       "a.country",
			"parent_handle": "a.parent_handle",
		},
	},
	"location": {
		keys: []string{
			"address", "building", "building_number", "province",
			"street_name", "unit", "locality", "city", "country", "postal_code",
		},
		colMap: map[string]string{
			"address":         "a.street_address",
			"building":        "a.building",
			"building_number": "a.building_number",
			"province":        "a.province",
			"street_name":     "a.street_name",
			"unit":            "a.unit",
			"locality":        "a.locality",
			"city":            "a.city",
			"country":         "a.country",
			"postal_code":     "a.postal_code",
		},
	},
	"netblock": {
		keys: []string{"cidr", "type"},
		colMap: map[string]string{
			"cidr": "a.netblock_cidr",
			"type": "a.ip_version",
		},
	},
	"organization": {
		keys: []string{"unique_id", "legal_name", "name", "jurisdiction", "registration_id"},
		colMap: map[string]string{
			"unique_id":       "a.unique_id",
			"legal_name":      "a.legal_name",
			"name":            "a.org_name",
			"jurisdiction":    "a.jurisdiction",
			"registration_id": "a.registration_id",
		},
	},
	"person": {
		keys: []string{"unique_id", "full_name", "first_name", "family_name", "middle_name"},
		colMap: map[string]string{
			"unique_id":   "a.unique_id",
			"full_name":   "a.full_name",
			"first_name":  "a.first_name",
			"family_name": "a.family_name",
			"middle_name": "a.middle_name",
		},
	},
	"phone": {
		keys: []string{"type", "e164", "raw", "country_code", "country_abbrev"},
		colMap: map[string]string{
			"type":           "a.number_type",
			"e164":           "a.e164",
			"raw":            "a.raw_number",
			"country_code":   "a.country_code",
			"country_abbrev": "a.country_abbrev",
		},
	},
	"product": {
		keys: []string{"unique_id", "product_name", "product_type", "category", "description", "country_of_origin"},
		colMap: map[string]string{
			"unique_id":         "a.unique_id",
			"product_name":      "a.product_name",
			"product_type":      "a.product_type",
			"category":          "a.category",
			"description":       "a.product_description",
			"country_of_origin": "a.country_of_origin",
		},
	},
	"productrelease": {
		keys: []string{"name"},
		colMap: map[string]string{
			"name": "a.release_name",
		},
	},
	"service": {
		keys: []string{"unique_id", "service_type", "output_length"},
		colMap: map[string]string{
			"unique_id":     "a.unique_id",
			"service_type":  "a.service_type",
			"output_length": "a.output_length",
		},
	},
	"tlscertificate": {
		keys: []string{
			"version", "serial_number", "subject_common_name", "issuer_common_name", "signature_algorithm", "public_key_algorithm",
		},
		colMap: map[string]string{
			"version":              "a.tls_version",
			"serial_number":        "a.serial_number",
			"subject_common_name":  "a.subject_common_name",
			"issuer_common_name":   "a.issuer_common_name",
			"signature_algorithm":  "a.signature_algorithm",
			"public_key_algorithm": "a.public_key_algorithm",
		},
	},
	"url": {
		keys: []string{"url", "host", "path", "port", "scheme"},
		colMap: map[string]string{
			"url":    "a.raw_url",
			"host":   "a.host",
			"path":   "a.url_path",
			"port":   "a.port",
			"scheme": "a.scheme",
		},
	},
}
