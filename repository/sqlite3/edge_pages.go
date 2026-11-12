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

// ReadEdgesPage reads one page of an entity's edges after a keyset cursor,
// in the order ReadEdgesLimited uses. updated_at is compared as the text
// SQLite stores and sorts, which is what the cursor's SortKey holds.
func (r *SqliteRepository) ReadEdgesPage(ctx context.Context, entity *types.Entity, direction string,
	since time.Time, after *types.EdgeCursor, limit int, labels ...string) ([]*types.Edge,
	*types.EdgeCursor, error) {
	if r == nil || r.rpool == nil || entity == nil {
		return nil, nil, errors.New("missing SQLite reader or entity")
	}
	if limit < 1 || limit > 500 {
		return nil, nil, errors.New("edge limit must be 1..500")
	}

	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid entity ID: %w", err)
	}

	var where []string
	var args []any
	switch direction {
	case "in":
		where, args = append(where, "e.to_entity_id = ?"), append(args, eid)
	case "out":
		where, args = append(where, "e.from_entity_id = ?"), append(args, eid)
	case "both":
		where, args = append(where, "(e.from_entity_id = ? OR e.to_entity_id = ?)"), append(args, eid, eid)
	default:
		return nil, nil, errors.New("invalid edge direction")
	}

	if !since.IsZero() {
		where, args = append(where, "e.updated_at >= ?"), append(args, since.UTC())
	}
	if len(labels) > 8 {
		return nil, nil, errors.New("too many edge labels")
	}
	if len(labels) > 0 {
		placeholders := make([]string, 0, len(labels))
		for _, l := range labels {
			if l == "" || len(l) > 128 {
				return nil, nil, errors.New("invalid edge label")
			}

			placeholders = append(placeholders, "?")
			args = append(args, strings.ToLower(l))
		}
		where = append(where, "e.label IN ("+strings.Join(placeholders, ",")+")")
	}
	if after != nil {
		last, err := strconv.ParseInt(after.EdgeID, 10, 64)
		if err != nil || after.SortKey == "" {
			return nil, nil, errors.New("invalid edge cursor")
		}

		where = append(where, "(e.updated_at < ? OR (e.updated_at = ? AND e.edge_id < ?))")
		args = append(args, after.SortKey, after.SortKey, last)
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
		return nil, nil, ctx.Err()
	case result = <-ch:
	}
	if result.Err != nil {
		return nil, nil, result.Err
	}

	rows := result.Rows
	defer rows.Close()

	out := make([]*types.Edge, 0, limit)
	var lastKey string
	for rows.Next() {
		if len(out) >= limit {
			e := out[len(out)-1]
			return out, &types.EdgeCursor{UpdatedAt: e.LastSeen, EdgeID: e.ID, SortKey: lastKey}, nil
		}

		var id, from, to int64
		var etype, raw, c, u string
		if err := rows.Scan(&id, &etype, &from, &to, &raw, &c, &u); err != nil {
			return nil, nil, err
		}

		rel, err := extractOAMRelation(etype, json.RawMessage(raw))
		if err != nil {
			return nil, nil, err
		}

		created, err := parseTimestamp(c)
		if err != nil {
			return nil, nil, err
		}

		updated, err := parseTimestamp(u)
		if err != nil {
			return nil, nil, err
		}

		lastKey = u
		out = append(out, &types.Edge{ID: strconv.FormatInt(id, 10), Relation: rel,
			FromEntity: &types.Entity{ID: strconv.FormatInt(from, 10)},
			ToEntity:   &types.Entity{ID: strconv.FormatInt(to, 10)}, CreatedAt: created, LastSeen: updated})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return out, nil, nil
}
