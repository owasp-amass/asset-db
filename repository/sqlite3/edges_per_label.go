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

// MaxEdgeLabelsPerRead is the most labels ReadEdgesPerLabel filters by.
const MaxEdgeLabelsPerRead = 64

// ReadEdgesPerLabel reads an entity's edges in one direction with up to
// perLabel edges for each label, newest first within a label, in one query.
// more lists the labels that have edges beyond perLabel. With no labels,
// every label is read. It returns what ReadEdgesLimited would for each label
// on its own.
func (r *SqliteRepository) ReadEdgesPerLabel(ctx context.Context, entity *types.Entity, direction string, since time.Time, perLabel int, labels ...string) ([]*types.Edge, []string, error) {
	if r == nil || r.rpool == nil || entity == nil {
		return nil, nil, errors.New("missing SQLite reader or entity")
	}
	if perLabel < 1 || perLabel > 500 {
		return nil, nil, errors.New("edge limit per label must be 1..500")
	}
	if len(labels) > MaxEdgeLabelsPerRead {
		return nil, nil, errors.New("too many edge labels")
	}

	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid entity ID: %w", err)
	}

	args := []any{eid}
	var where []string
	switch direction {
	case "in":
		where = append(where, "e.to_entity_id = ?")
	case "out":
		where = append(where, "e.from_entity_id = ?")
	case "both":
		where = append(where, "(e.from_entity_id = ? OR e.to_entity_id = ?)")
		args = append(args, eid)
	default:
		return nil, nil, errors.New("invalid edge direction")
	}
	if !since.IsZero() {
		where = append(where, "e.updated_at >= ?")
		args = append(args, since.UTC())
	}
	if len(labels) > 0 {
		for _, l := range labels {
			if l == "" || len(l) > 128 {
				return nil, nil, errors.New("invalid edge label")
			}
			args = append(args, strings.ToLower(l))
		}
		where = append(where, "e.label IN ("+strings.TrimSuffix(strings.Repeat("?,", len(labels)), ",")+")")
	}

	args = append(args, perLabel+1)
	query := `SELECT x.edge_id,x.etype,x.from_entity_id,x.to_entity_id,x.content,x.created_at,x.updated_at,x.label,x.rn
        FROM (SELECT e.edge_id,t.name AS etype,e.from_entity_id,e.to_entity_id,e.content,e.created_at,e.updated_at,
            e.label,ROW_NUMBER() OVER (PARTITION BY e.label ORDER BY e.updated_at DESC,e.edge_id DESC) AS rn
            FROM edge e JOIN edge_type_lu t ON t.id=e.etype_id
            WHERE ` + strings.Join(where, " AND ") + `) x
        WHERE x.rn <= ? ORDER BY x.label,x.rn`
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
	var out []*types.Edge
	var more []string
	for rows.Next() {
		var id, from, to, rn int64
		var etype, raw, c, u, label string
		if err := rows.Scan(&id, &etype, &from, &to, &raw, &c, &u, &label, &rn); err != nil {
			return nil, nil, err
		}
		if rn > int64(perLabel) {
			more = append(more, label)
			continue
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

		out = append(out, &types.Edge{ID: strconv.FormatInt(id, 10), Relation: rel,
			FromEntity: &types.Entity{ID: strconv.FormatInt(from, 10)},
			ToEntity:   &types.Entity{ID: strconv.FormatInt(to, 10)}, CreatedAt: created, LastSeen: updated})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return out, more, nil
}
