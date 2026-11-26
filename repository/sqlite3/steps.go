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

// ReadSteps returns, each once, the edges whose source is one of ids and that
// a forward step matches, and those whose destination is one of ids and that
// a backward step matches, in one query, with no limit per entity.
func (r *SqliteRepository) ReadSteps(ctx context.Context, ids []string, steps []types.Step, since time.Time) ([]*types.Edge, error) {
	if r == nil || r.rpool == nil {
		return nil, errors.New("missing SQLite reader")
	}
	if len(ids) > MaxEntitiesByIds {
		return nil, fmt.Errorf("at most %d entity IDs may be read at once", MaxEntitiesByIds)
	}
	forward, backward, err := types.CheckSteps(steps)
	if err != nil {
		return nil, err
	}

	eids := make([]any, 0, len(ids))
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

	var args []any
	// branch selects the edges one direction's steps follow from the ids:
	// owner is the end that is in ids.
	branch := func(steps []types.Step, owner string) string {
		values := make([]string, 0, len(steps))
		for _, s := range steps {
			values = append(values, "(?,?,?,?)")
			args = append(args, s.FromType, s.Label, s.RelationType, s.ToType)
		}

		args = append(args, eids...)
		q := `SELECT e.edge_id,t.name AS etype,e.from_entity_id,e.to_entity_id,e.content,e.created_at,e.updated_at
            FROM edge e
            JOIN edge_type_lu t ON t.id=e.etype_id
            JOIN entity fe ON fe.entity_id=e.from_entity_id
            JOIN entity_type_lu ft ON ft.id=fe.etype_id
            JOIN entity te ON te.entity_id=e.to_entity_id
            JOIN entity_type_lu tt ON tt.id=te.etype_id
            JOIN (VALUES ` + strings.Join(values, ",") + `) AS s
              ON s.column1=lower(ft.name) AND s.column2=lower(e.label) AND s.column3=lower(t.name)
             AND s.column4=lower(tt.name)
            WHERE ` + owner + ` IN (` + strings.TrimSuffix(strings.Repeat("?,", len(eids)), ",") + `)`
		if !since.IsZero() {
			q += " AND e.updated_at >= ?"
			args = append(args, since.UTC())
		}
		return q
	}

	var parts []string
	if len(forward) > 0 {
		parts = append(parts, branch(forward, "e.from_entity_id"))
	}
	if len(backward) > 0 {
		parts = append(parts, branch(backward, "e.to_entity_id"))
	}
	query := strings.Join(parts, " UNION ")

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: query, SQLText: query, Args: args, Result: ch})
	var result *rowsReadResult
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result = <-ch:
	}
	if result.Err != nil {
		return nil, result.Err
	}

	rows := result.Rows
	defer rows.Close()

	var out []*types.Edge
	for rows.Next() {
		var id, from, to int64
		var etype, raw, c, u string
		if err := rows.Scan(&id, &etype, &from, &to, &raw, &c, &u); err != nil {
			return nil, err
		}

		rel, err := extractOAMRelation(etype, json.RawMessage(raw))
		if err != nil {
			return nil, err
		}

		created, err := parseTimestamp(c)
		if err != nil {
			return nil, err
		}

		updated, err := parseTimestamp(u)
		if err != nil {
			return nil, err
		}

		out = append(out, &types.Edge{ID: strconv.FormatInt(id, 10), Relation: rel,
			FromEntity: &types.Entity{ID: strconv.FormatInt(from, 10)},
			ToEntity:   &types.Entity{ID: strconv.FormatInt(to, 10)}, CreatedAt: created, LastSeen: updated})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}
