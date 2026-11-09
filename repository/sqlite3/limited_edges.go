// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/asset-db/types"
)

// ReadEdgesLimited bounds the SQL result set rather than materializing all
// matching relationships. It intentionally does not change legacy queries.
func (r *SqliteRepository) ReadEdgesLimited(ctx context.Context, entity *types.Entity, direction string, since time.Time, limit int, labels ...string) ([]*types.Edge, bool, error) {
	if r == nil || r.rpool == nil || entity == nil {
		return nil, false, errors.New("missing SQLite reader or entity")
	}
	if limit < 1 || limit > 500 {
		return nil, false, errors.New("edge limit must be 1..500")
	}
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, false, fmt.Errorf("invalid entity ID: %w", err)
	}
	var expr string
	switch direction {
	case "in":
		expr = "e.to_entity_id = ?"
	case "out":
		expr = "e.from_entity_id = ?"
	case "both":
		expr = "(e.from_entity_id = ? OR e.to_entity_id = ?)"
	default:
		return nil, false, errors.New("invalid edge direction")
	}
	args := []any{eid}
	if direction == "both" {
		args = append(args, eid)
	}
	var where = []string{expr}
	if !since.IsZero() {
		where = append(where, "e.updated_at >= ?")
		args = append(args, since.UTC())
	}
	if len(labels) > 8 {
		return nil, false, errors.New("too many edge labels")
	}
	if len(labels) > 0 {
		placeholders := make([]string, 0, len(labels))
		for _, l := range labels {
			if l == "" || len(l) > 128 {
				return nil, false, errors.New("invalid edge label")
			}
			placeholders = append(placeholders, "?")
			args = append(args, strings.ToLower(l))
		}
		where = append(where, "e.label IN ("+strings.Join(placeholders, ",")+")")
	}
	query := `SELECT e.edge_id,t.name,e.from_entity_id,e.to_entity_id,e.content,e.created_at,e.updated_at
        FROM edge e JOIN edge_type_lu t ON t.id=e.etype_id
        WHERE ` + strings.Join(where, " AND ") + ` ORDER BY e.updated_at DESC,e.edge_id DESC LIMIT ?`
	args = append(args, limit+1)
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
	rows := result.Rows
	defer rows.Close()
	out := make([]*types.Edge, 0, limit)
	for rows.Next() {
		if len(out) >= limit {
			return out, true, nil
		}
		var id, from, to int64
		var etype, raw, c, u string
		if err := rows.Scan(&id, &etype, &from, &to, &raw, &c, &u); err != nil {
			return nil, false, err
		}
		rel, err := extractOAMRelation(etype, json.RawMessage(raw))
		if err != nil {
			return nil, false, err
		}
		created, err := parseTimestamp(c)
		if err != nil {
			return nil, false, err
		}
		updated, err := parseTimestamp(u)
		if err != nil {
			return nil, false, err
		}
		out = append(out, &types.Edge{ID: strconv.FormatInt(id, 10), Relation: rel,
			FromEntity: &types.Entity{ID: strconv.FormatInt(from, 10)}, ToEntity: &types.Entity{ID: strconv.FormatInt(to, 10)}, CreatedAt: created, LastSeen: updated})
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return out, false, nil
}
