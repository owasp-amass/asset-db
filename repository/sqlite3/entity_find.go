// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

func (r *SqliteRepository) FindEntityById(ctx context.Context, id string) (*types.Entity, error) {
	entityId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return nil, err
	}
	return r.queries.FindEntityByID(ctx, int64(entityId))
}

func (r *SqliteRepository) FindEntitiesByContent(ctx context.Context, etype string, since time.Time, filters types.ContentFilters) ([]*types.Entity, error) {
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

func (r *SqliteRepository) FindOneEntityByContent(ctx context.Context, etype string, since time.Time, filters types.ContentFilters) (*types.Entity, error) {
	ent, err := r.queries.FindOneByContent(ctx, etype, filters)
	if err != nil {
		return nil, err
	}
	if ent.LastSeen.Before(since) {
		return nil, errors.New("entity not found")
	}
	return ent, nil
}

func (r *SqliteRepository) FindEntitiesByType(ctx context.Context, atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
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

// FindOneByContent returns exactly one (first by updated_at desc)
func (r *Queries) FindOneByContent(ctx context.Context, assetType string, filters types.ContentFilters) (*types.Entity, error) {
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
func (r *Queries) FindByContent(ctx context.Context, assetType string, filters types.ContentFilters, limit int) ([]*types.Entity, error) {
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
	defer func() { _ = rows.Close() }()

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
	defer func() { _ = rows.Close() }()

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
	defer func() { _ = rows.Close() }()

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
