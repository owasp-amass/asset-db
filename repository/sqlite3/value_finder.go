// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/internal/valuequery"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// FindEntitiesByTagValue implements repository.ValueFinder.
func (r *SqliteRepository) FindEntitiesByTagValue(ctx context.Context, atype oam.AssetType, name, value string, contains bool, since time.Time, limit int) ([]*types.Entity, bool, error) {
	if r == nil || r.rpool == nil {
		return nil, false, errors.New("missing SQLite reader")
	}
	if err := valuequery.Check(atype, name, value, limit); err != nil {
		return nil, false, err
	}

	match, arg := "g.property_value = ?", any(value)
	if contains {
		match, arg = `lower(g.property_value) LIKE ? ESCAPE '\'`, valuequery.LikePattern(value)
	}

	args := []any{normalizeType(string(atype)), name, arg}
	query := `SELECT DISTINCT e.entity_id FROM entity_tag g
        JOIN entity e ON e.entity_id = g.entity_id
        JOIN entity_type_lu t ON t.id = e.etype_id AND t.name = ?
        WHERE g.property_name = ? AND ` + match
	if !since.IsZero() {
		query += " AND g.updated_at >= ?"
		args = append(args, since.UTC())
	}

	return r.entitiesByID(ctx, query+" ORDER BY e.entity_id LIMIT ?", append(args, limit+1), limit)
}

// FindEntitiesByAttribute implements repository.ValueFinder.
func (r *SqliteRepository) FindEntitiesByAttribute(ctx context.Context, atype oam.AssetType, key, value string, contains bool, since time.Time, limit int) ([]*types.Entity, bool, error) {
	if r == nil || r.rpool == nil {
		return nil, false, errors.New("missing SQLite reader")
	}
	if err := valuequery.Check(atype, key, value, limit); err != nil {
		return nil, false, err
	}
	if err := valuequery.CheckKey(key); err != nil {
		return nil, false, err
	}

	table := validateAssetTable(string(atype))
	if table == "" {
		return nil, false, fmt.Errorf("unknown asset type %q", atype)
	}

	// A few asset values are promoted out of attrs into dedicated columns
	// (Identifier.id -> id_value, URL.url -> raw_url), so attrs does not carry
	// them; query the column so the search actually matches. Everything else
	// lives in attrs, where the json_extract index applies.
	valueExpr := fmt.Sprintf("json_extract(a.attrs, '$.%s')", key)
	if col := promotedColumn(table, key); col != "" {
		valueExpr = "a." + col
	}
	match, arg := valueExpr+" = ?", any(value)
	if contains {
		match = fmt.Sprintf(`lower(%s) LIKE ? ESCAPE '\'`, valueExpr)
		arg = valuequery.LikePattern(value)
	}

	args := []any{table, arg}
	query := fmt.Sprintf(`SELECT e.entity_id FROM entity e
        JOIN entity_type_lu t ON t.id = e.etype_id AND t.name = ?
        JOIN %s a ON a.id = e.row_id
        WHERE %s`, table, match)
	if !since.IsZero() {
		query += " AND e.updated_at >= ?"
		args = append(args, since.UTC())
	}

	return r.entitiesByID(ctx, query+" ORDER BY e.entity_id LIMIT ?", append(args, limit+1), limit)
}

// promotedColumn maps an OAM logical field that the writer promotes out of
// attrs into a dedicated column (so attrs does not carry it) to that column
// name, or "" when the field lives in attrs. Mirrors the column resolution in
// FindEntitiesByContent so value lookups match wherever the field is stored.
func promotedColumn(table, key string) string {
	switch table + "." + key {
	case "identifier.id":
		return "id_value"
	case "url.url":
		return "raw_url"
	}

	return ""
}

// entitiesByID runs a query selecting entity IDs and loads up to limit of
// them, reporting whether more matched.
func (r *SqliteRepository) entitiesByID(ctx context.Context, query string, args []any, limit int) ([]*types.Entity, bool, error) {
	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: query, SQLText: query, Args: args, Result: ch})

	var result *rowsReadResult
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case result = <-ch:
	}
	if result.Err != nil {
		return nil, false, result.Err
	}

	var ids []int64
	rows := result.Rows
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
