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

// MaxEdgeLabelsPerRead is the most labels ReadEdgesPerLabel filters by.
const MaxEdgeLabelsPerRead = 64

// ReadEdgesPerLabel reads an entity's edges in one direction with up to
// perLabel edges for each label, newest first within a label, in one query.
// more lists the labels that have edges beyond perLabel. With no labels,
// every label is read. It returns what ReadEdgesLimited would for each label
// on its own.
func (r *PostgresRepository) ReadEdgesPerLabel(ctx context.Context, entity *types.Entity, direction string, since time.Time, perLabel int, labels ...string) ([]*types.Edge, []string, error) {
	if r == nil || r.DB == nil || entity == nil {
		return nil, nil, errors.New("missing PostgreSQL reader or entity")
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

	args = append(args, perLabel+1)
	query := `SELECT x.edge_id,x.etype,x.from_entity_id,x.to_entity_id,x.content,x.created_at,x.updated_at,x.label,x.rn
        FROM (SELECT e.edge_id,t.name AS etype,e.from_entity_id,e.to_entity_id,e.content,e.created_at,e.updated_at,
            e.label,ROW_NUMBER() OVER (PARTITION BY e.label ORDER BY e.updated_at DESC,e.edge_id DESC) AS rn
            FROM public.edge e JOIN public.edge_type_lu t ON t.id=e.etype_id
            WHERE ` + strings.Join(where, " AND ") + `) x
        WHERE x.rn <= $` + strconv.Itoa(len(args)) + ` ORDER BY x.label,x.rn`
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}

	defer rows.Close()

	var out []*types.Edge
	var more []string
	for rows.Next() {
		var id, from, to, rn int64
		var etype, raw, label string
		var c, u time.Time
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

		out = append(out, &types.Edge{ID: strconv.FormatInt(id, 10), Relation: rel,
			FromEntity: &types.Entity{ID: strconv.FormatInt(from, 10)},
			ToEntity:   &types.Entity{ID: strconv.FormatInt(to, 10)}, CreatedAt: c.UTC(), LastSeen: u.UTC()})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return out, more, nil
}
