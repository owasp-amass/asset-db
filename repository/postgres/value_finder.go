// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/asset-db/internal/valuequery"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// FindEntitiesByTagValue implements repository.ValueFinder.
func (r *PostgresRepository) FindEntitiesByTagValue(ctx context.Context, atype oam.AssetType, name, value string, contains bool, since time.Time, limit int) ([]*types.Entity, bool, error) {
	return r.FindEntitiesByTagValueAfter(ctx, atype, name, value, contains, since, "", limit)
}

// FindEntitiesByTagValueAfter implements repository.ValueFinder.
func (r *PostgresRepository) FindEntitiesByTagValueAfter(ctx context.Context, atype oam.AssetType, name, value string,
	contains bool, since time.Time, after string, limit int) ([]*types.Entity, bool, error) {
	if r == nil || r.DB == nil {
		return nil, false, errors.New("missing PostgreSQL reader")
	}
	if err := valuequery.Check(atype, name, value, limit); err != nil {
		return nil, false, err
	}
	afterID, err := valuequery.After(after)
	if err != nil {
		return nil, false, err
	}

	// An exact value matches the index on the value's SHA-256 (values can be
	// longer than a B-tree entry); lower(property_value) LIKE matches the
	// trigram index on the same expression.
	match, arg := "public.tag_value_key(g.property_value) = public.tag_value_key($3::text) AND g.property_value = $3",
		any(value)
	if contains {
		match, arg = `lower(g.property_value) LIKE $3 ESCAPE '\'`, valuequery.LikePattern(value)
	}

	args := []any{normalizeType(string(atype)), name, arg}
	query := `SELECT DISTINCT e.entity_id FROM public.entity_tag g
        JOIN public.entity e ON e.entity_id = g.entity_id
        JOIN public.entity_type_lu t ON t.id = e.etype_id AND t.name = $1
        WHERE g.property_name = $2 AND ` + match
	if !since.IsZero() {
		args = append(args, since.UTC())
		query += fmt.Sprintf(" AND g.updated_at >= $%d", len(args))
	}
	if afterID > 0 {
		args = append(args, afterID)
		query += fmt.Sprintf(" AND e.entity_id > $%d", len(args))
	}

	args = append(args, limit+1)
	return r.entitiesByID(ctx, query+fmt.Sprintf(" ORDER BY e.entity_id LIMIT $%d", len(args)), args, limit)
}

// FindEntitiesByAttribute implements repository.ValueFinder.
func (r *PostgresRepository) FindEntitiesByAttribute(ctx context.Context, atype oam.AssetType, key, value string, contains bool, since time.Time, limit int) ([]*types.Entity, bool, error) {
	return r.FindEntitiesByAttributeAfter(ctx, atype, key, value, contains, since, "", limit)
}

// FindEntitiesByAttributeAfter implements repository.ValueFinder.
func (r *PostgresRepository) FindEntitiesByAttributeAfter(ctx context.Context, atype oam.AssetType, key, value string,
	contains bool, since time.Time, after string, limit int) ([]*types.Entity, bool, error) {
	if r == nil || r.DB == nil {
		return nil, false, errors.New("missing PostgreSQL reader")
	}
	if err := valuequery.Check(atype, key, value, limit); err != nil {
		return nil, false, err
	}
	afterID, err := valuequery.After(after)
	if err != nil {
		return nil, false, err
	}
	if err := valuequery.CheckKey(key); err != nil {
		return nil, false, err
	}

	table := assetTable(atype)
	if table == "" {
		return nil, false, fmt.Errorf("unknown asset type %q", atype)
	}

	// A few asset values are promoted out of attrs into dedicated, indexed
	// columns (e.g. Identifier.id -> id_value, URL.url -> raw_url), so attrs
	// does not carry them; query the column so the search actually matches and
	// uses the column's index (exact) or trigram index (contains). Everything
	// else lives in attrs, where the (attrs->>'key') index applies.
	valueExpr := fmt.Sprintf("a.attrs->>'%s'", key)
	if col := promotedColumn(table, key); col != "" {
		valueExpr = "a." + col
	}
	match, arg := fmt.Sprintf("(%s) = $2", valueExpr), any(value)
	if contains {
		match = fmt.Sprintf(`lower(%s) LIKE $2 ESCAPE '\'`, valueExpr)
		arg = valuequery.LikePattern(value)
	}

	args := []any{table, arg}
	query := fmt.Sprintf(`SELECT e.entity_id FROM public.entity e
        JOIN public.entity_type_lu t ON t.id = e.etype_id AND t.name = $1
        JOIN public.%s a ON a.id = e.row_id
        WHERE %s`, table, match)
	if !since.IsZero() {
		args = append(args, since.UTC())
		query += fmt.Sprintf(" AND e.updated_at >= $%d", len(args))
	}
	if afterID > 0 {
		args = append(args, afterID)
		query += fmt.Sprintf(" AND e.entity_id > $%d", len(args))
	}

	args = append(args, limit+1)
	return r.entitiesByID(ctx, query+fmt.Sprintf(" ORDER BY e.entity_id LIMIT $%d", len(args)), args, limit)
}

// assetTable returns the table of an OAM asset type, or "" for an unknown
// type.
func assetTable(atype oam.AssetType) string {
	for _, t := range oam.AssetList {
		if strings.EqualFold(string(t), string(atype)) {
			return normalizeType(string(t))
		}
	}

	return ""
}

// promotedColumn maps an OAM logical field that FindEntitiesByContent already
// resolves to a dedicated column (because the writer promotes it out of attrs)
// to that column name, or "" when the field lives in attrs. Keeping this list
// beside the attrs fallback keeps value lookups matching whichever place the
// writer actually stores the field.
func promotedColumn(table, key string) string {
	switch table + "." + key {
	case "identifier.id":
		return "id_value"
	case "identifier.id_type":
		return "id_type"
	case "url.url":
		return "raw_url"
	}

	return ""
}

// entitiesByID runs a query selecting entity IDs and loads up to limit of
// them, reporting whether more matched.
func (r *PostgresRepository) entitiesByID(ctx context.Context, query string, args []any, limit int) ([]*types.Entity, bool, error) {
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, false, err
		}

		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, false, err
	}

	_ = rows.Close()
	more := len(ids) > limit
	if more {
		ids = ids[:limit]
	}

	// the entities in one read, in the query's order
	strs := make([]string, 0, len(ids))
	for _, id := range ids {
		strs = append(strs, strconv.FormatInt(id, 10))
	}
	ents, err := r.FindEntitiesByIds(ctx, strs)
	if err != nil {
		return nil, false, err
	}

	byID := make(map[string]*types.Entity, len(ents))
	for _, e := range ents {
		byID[e.ID] = e
	}

	out := make([]*types.Entity, 0, len(strs))
	for _, id := range strs {
		if e, ok := byID[id]; ok {
			out = append(out, e)
		}
	}

	return out, more, nil
}
