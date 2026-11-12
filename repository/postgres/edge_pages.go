// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

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
// in the order ReadEdgesLimited uses. The cursor's SortKey holds updated_at
// at full precision, so a tie on updated_at is broken by the edge ID.
func (r *PostgresRepository) ReadEdgesPage(ctx context.Context, entity *types.Entity, direction string,
	since time.Time, after *types.EdgeCursor, limit int, labels ...string) ([]*types.Edge, *types.EdgeCursor, error) {
	if r == nil || r.DB == nil || entity == nil {
		return nil, nil, errors.New("missing PostgreSQL reader or entity")
	}
	if limit < 1 || limit > 500 {
		return nil, nil, errors.New("edge limit must be 1..500")
	}

	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid entity ID: %w", err)
	}

	args := []any{eid}
	var where []string
	switch direction {
	case "in":
		where = append(where, "e.to_entity_id=$1")
	case "out":
		where = append(where, "e.from_entity_id=$1")
	case "both":
		where = append(where, "(e.from_entity_id=$1 OR e.to_entity_id=$1)")
	default:
		return nil, nil, errors.New("invalid edge direction")
	}

	if !since.IsZero() {
		args = append(args, since.UTC())
		where = append(where, fmt.Sprintf("e.updated_at >= $%d", len(args)))
	}
	if len(labels) > 8 {
		return nil, nil, errors.New("too many edge labels")
	}
	if len(labels) > 0 {
		names := make([]string, 0, len(labels))
		for _, l := range labels {
			if l == "" || len(l) > 128 {
				return nil, nil, errors.New("invalid edge label")
			}

			args = append(args, strings.ToLower(l))
			names = append(names, fmt.Sprintf("$%d", len(args)))
		}
		where = append(where, "e.label IN ("+strings.Join(names, ",")+")")
	}
	if after != nil {
		last, err := strconv.ParseInt(after.EdgeID, 10, 64)
		if err != nil {
			return nil, nil, errors.New("invalid edge cursor")
		}

		at, err := time.Parse(time.RFC3339Nano, after.SortKey)
		if err != nil {
			return nil, nil, errors.New("invalid edge cursor")
		}

		args = append(args, at, last)
		where = append(where, fmt.Sprintf("(e.updated_at, e.edge_id) < ($%d, $%d)", len(args)-1, len(args)))
	}

	args = append(args, limit+1)
	query := `SELECT e.edge_id,t.name,e.from_entity_id,e.to_entity_id,e.content,e.created_at,e.updated_at
        FROM public.edge e JOIN public.edge_type_lu t ON t.id=e.etype_id
        WHERE ` + strings.Join(where, " AND ") +
		fmt.Sprintf(` ORDER BY e.updated_at DESC,e.edge_id DESC LIMIT $%d`, len(args))
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	out := make([]*types.Edge, 0, limit)
	for rows.Next() {
		if len(out) >= limit {
			e := out[len(out)-1]
			return out, &types.EdgeCursor{UpdatedAt: e.LastSeen, EdgeID: e.ID,
				SortKey: e.LastSeen.Format(time.RFC3339Nano)}, nil
		}

		var id, from, to int64
		var etype, raw string
		var c, u time.Time
		if err := rows.Scan(&id, &etype, &from, &to, &raw, &c, &u); err != nil {
			return nil, nil, err
		}

		rel, err := extractOAMRelation(etype, json.RawMessage(raw))
		if err != nil {
			return nil, nil, err
		}

		out = append(out, &types.Edge{ID: strconv.FormatInt(id, 10), Relation: rel,
			FromEntity: &types.Entity{ID: strconv.FormatInt(from, 10)},
			ToEntity:   &types.Entity{ID: strconv.FormatInt(to, 10)}, CreatedAt: c.UTC(), LastSeen: u.UTC()})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return out, nil, nil
}
