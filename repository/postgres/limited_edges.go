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

// ReadEdgesLimited directly queries the base table with a server-side LIMIT
// so the AI agent does not materialize an unbounded relation neighborhood.
func (r *PostgresRepository) ReadEdgesLimited(ctx context.Context, entity *types.Entity, direction string, since time.Time, limit int, labels ...string) ([]*types.Edge, bool, error) {
	if r == nil || r.DB == nil || entity == nil {
		return nil, false, errors.New("missing PostgreSQL reader or entity")
	}
	if limit < 1 || limit > 500 {
		return nil, false, errors.New("edge limit must be 1..500")
	}
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, false, fmt.Errorf("invalid entity ID: %w", err)
	}
	var expr string
	args := []any{eid}
	switch direction {
	case "in":
		expr = "e.to_entity_id=$1"
	case "out":
		expr = "e.from_entity_id=$1"
	case "both":
		expr = "(e.from_entity_id=$1 OR e.to_entity_id=$1)"
	default:
		return nil, false, errors.New("invalid edge direction")
	}
	where := []string{expr}
	if !since.IsZero() {
		args = append(args, since.UTC())
		where = append(where, fmt.Sprintf("e.updated_at >= $%d", len(args)))
	}
	if len(labels) > 8 {
		return nil, false, errors.New("too many edge labels")
	}
	if len(labels) > 0 {
		names := make([]string, 0, len(labels))
		for _, l := range labels {
			if l == "" || len(l) > 128 {
				return nil, false, errors.New("invalid edge label")
			}
			args = append(args, strings.ToLower(l))
			names = append(names, fmt.Sprintf("$%d", len(args)))
		}
		where = append(where, "e.label IN ("+strings.Join(names, ",")+")")
	}
	args = append(args, limit+1)
	query := `SELECT e.edge_id,t.name,e.from_entity_id,e.to_entity_id,e.content,e.created_at,e.updated_at
        FROM public.edge e JOIN public.edge_type_lu t ON t.id=e.etype_id
        WHERE ` + strings.Join(where, " AND ") + fmt.Sprintf(` ORDER BY e.updated_at DESC,e.edge_id DESC LIMIT $%d`, len(args))
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := make([]*types.Edge, 0, limit)
	for rows.Next() {
		if len(out) >= limit {
			return out, true, nil
		}
		var id, from, to int64
		var etype, raw string
		var c, u time.Time
		if err := rows.Scan(&id, &etype, &from, &to, &raw, &c, &u); err != nil {
			return nil, false, err
		}
		rel, err := extractOAMRelation(etype, json.RawMessage(raw))
		if err != nil {
			return nil, false, err
		}
		out = append(out, &types.Edge{ID: strconv.FormatInt(id, 10), Relation: rel,
			FromEntity: &types.Entity{ID: strconv.FormatInt(from, 10)}, ToEntity: &types.Entity{ID: strconv.FormatInt(to, 10)}, CreatedAt: c.UTC(), LastSeen: u.UTC()})
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return out, false, nil
}
