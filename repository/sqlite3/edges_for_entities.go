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

// ReadEdgesForEntities reads the edges of many entities in one direction
// ("in" or "out") with up to perEntity edges for each, newest first, in one
// query. The result holds each entity's edges by entity ID; more lists the
// entities with edges beyond perEntity. Each entity's edges are what
// ReadEdgesLimited returns for it alone.
func (r *SqliteRepository) ReadEdgesForEntities(ctx context.Context, ids []string, direction string, since time.Time, perEntity int, labels ...string) (map[string][]*types.Edge, []string, error) {
	if r == nil || r.rpool == nil {
		return nil, nil, errors.New("missing SQLite reader")
	}
	if perEntity < 1 || perEntity > 500 {
		return nil, nil, errors.New("edge limit per entity must be 1..500")
	}
	if len(ids) > MaxEntitiesByIds {
		return nil, nil, fmt.Errorf("at most %d entity IDs may be read at once", MaxEntitiesByIds)
	}
	if len(labels) > MaxEdgeLabelsPerRead {
		return nil, nil, errors.New("too many edge labels")
	}

	var owner string
	switch direction {
	case "in":
		owner = "e.to_entity_id"
	case "out":
		owner = "e.from_entity_id"
	default:
		return nil, nil, errors.New("edge direction must be in or out")
	}

	args := make([]any, 0, len(ids)+len(labels)+2)
	for _, id := range ids {
		eid, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid entity ID %q: %w", id, err)
		}

		args = append(args, eid)
	}
	if len(args) == 0 {
		return map[string][]*types.Edge{}, nil, nil
	}

	where := []string{owner + " IN (" + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + ")"}
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

	args = append(args, perEntity+1)
	query := `SELECT x.owner,x.edge_id,x.etype,x.from_entity_id,x.to_entity_id,x.content,x.created_at,x.updated_at,x.rn
        FROM (SELECT ` + owner + ` AS owner,e.edge_id,t.name AS etype,e.from_entity_id,e.to_entity_id,e.content,
            e.created_at,e.updated_at,ROW_NUMBER() OVER (PARTITION BY ` + owner + `
            ORDER BY e.updated_at DESC,e.edge_id DESC) AS rn
            FROM edge e JOIN edge_type_lu t ON t.id=e.etype_id
            WHERE ` + strings.Join(where, " AND ") + `) x
        WHERE x.rn <= ? ORDER BY x.owner,x.rn`
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

	out := make(map[string][]*types.Edge, len(ids))
	var more []string
	for rows.Next() {
		var own, id, from, to, rn int64
		var etype, raw, c, u string
		if err := rows.Scan(&own, &id, &etype, &from, &to, &raw, &c, &u, &rn); err != nil {
			return nil, nil, err
		}

		key := strconv.FormatInt(own, 10)
		if rn > int64(perEntity) {
			more = append(more, key)
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

		out[key] = append(out[key], &types.Edge{ID: strconv.FormatInt(id, 10), Relation: rel,
			FromEntity: &types.Entity{ID: strconv.FormatInt(from, 10)},
			ToEntity:   &types.Entity{ID: strconv.FormatInt(to, 10)}, CreatedAt: created, LastSeen: updated})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return out, more, nil
}
