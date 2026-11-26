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
	"time"

	"github.com/owasp-amass/asset-db/types"
)

// ReadSteps returns, each once, the edges whose source is one of ids and that
// a forward step matches, and those whose destination is one of ids and that
// a backward step matches, in one query, with no limit per entity.
func (r *PostgresRepository) ReadSteps(ctx context.Context, ids []string, steps []types.Step, since time.Time) ([]*types.Edge, error) {
	if r == nil || r.DB == nil {
		return nil, errors.New("missing PostgreSQL reader")
	}
	if len(ids) > MaxEntitiesByIds {
		return nil, fmt.Errorf("at most %d entity IDs may be read at once", MaxEntitiesByIds)
	}
	forward, backward, err := types.CheckSteps(steps)
	if err != nil {
		return nil, err
	}

	eids := make([]int64, 0, len(ids))
	for _, id := range ids {
		eid, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid entity ID %q: %w", id, err)
		}

		eids = append(eids, eid)
	}
	if len(eids) == 0 {
		return nil, nil
	}

	args := []any{eids}
	seen := ""
	if !since.IsZero() {
		args = append(args, since.UTC())
		seen = " AND e.updated_at >= $2"
	}
	// branch selects the edges one direction's steps follow from the ids:
	// owner is the end that is in ids.
	branch := func(steps []types.Step, owner string) string {
		var from, label, rel, to []string
		for _, s := range steps {
			from, label, rel, to = append(from, s.FromType), append(label, s.Label), append(rel, s.RelationType),
				append(to, s.ToType)
		}

		n := len(args)
		args = append(args, from, label, rel, to)
		return fmt.Sprintf(`SELECT e.edge_id,t.name AS etype,e.from_entity_id,e.to_entity_id,e.content,e.created_at,e.updated_at
            FROM public.edge e
            JOIN public.edge_type_lu t ON t.id=e.etype_id
            JOIN public.entity fe ON fe.entity_id=e.from_entity_id
            JOIN public.entity_type_lu ft ON ft.id=fe.etype_id
            JOIN public.entity te ON te.entity_id=e.to_entity_id
            JOIN public.entity_type_lu tt ON tt.id=te.etype_id
            JOIN unnest($%d::text[],$%d::text[],$%d::text[],$%d::text[]) AS s(from_t,label,rel_t,to_t)
              ON s.from_t=lower(ft.name::text) AND s.label=lower(e.label::text) AND s.rel_t=lower(t.name::text)
             AND s.to_t=lower(tt.name::text)
            WHERE %s = ANY($1)%s`, n+1, n+2, n+3, n+4, owner, seen)
	}

	var parts []string
	if len(forward) > 0 {
		parts = append(parts, branch(forward, "e.from_entity_id"))
	}
	if len(backward) > 0 {
		parts = append(parts, branch(backward, "e.to_entity_id"))
	}
	query := parts[0]
	if len(parts) > 1 {
		query += " UNION " + parts[1]
	}

	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var out []*types.Edge
	for rows.Next() {
		var id, from, to int64
		var etype, raw string
		var c, u time.Time
		if err := rows.Scan(&id, &etype, &from, &to, &raw, &c, &u); err != nil {
			return nil, err
		}

		rel, err := extractOAMRelation(etype, json.RawMessage(raw))
		if err != nil {
			return nil, err
		}

		out = append(out, &types.Edge{ID: strconv.FormatInt(id, 10), Relation: rel,
			FromEntity: &types.Entity{ID: strconv.FormatInt(from, 10)},
			ToEntity:   &types.Entity{ID: strconv.FormatInt(to, 10)}, CreatedAt: c.UTC(), LastSeen: u.UTC()})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}
