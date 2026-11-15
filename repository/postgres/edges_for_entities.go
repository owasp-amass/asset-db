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

// ReadEdgesForEntities reads the edges of many entities in one direction
// ("in" or "out") with up to perEntity edges for each, newest first, in one
// query. The result holds each entity's edges by entity ID; more lists the
// entities with edges beyond perEntity. Each entity's edges are what
// ReadEdgesLimited returns for it alone.
func (r *PostgresRepository) ReadEdgesForEntities(ctx context.Context, ids []string, direction string, since time.Time, perEntity int, labels ...string) (map[string][]*types.Edge, []string, error) {
	if r == nil || r.DB == nil {
		return nil, nil, errors.New("missing PostgreSQL reader")
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

	eids := make([]int64, 0, len(ids))
	for _, id := range ids {
		eid, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid entity ID %q: %w", id, err)
		}

		eids = append(eids, eid)
	}
	if len(eids) == 0 {
		return map[string][]*types.Edge{}, nil, nil
	}

	args := []any{eids}
	where := []string{owner + " = ANY($1)"}
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

	args = append(args, perEntity+1)
	query := `SELECT x.owner,x.edge_id,x.etype,x.from_entity_id,x.to_entity_id,x.content,x.created_at,x.updated_at,x.rn
        FROM (SELECT ` + owner + ` AS owner,e.edge_id,t.name AS etype,e.from_entity_id,e.to_entity_id,e.content,
            e.created_at,e.updated_at,ROW_NUMBER() OVER (PARTITION BY ` + owner + `
            ORDER BY e.updated_at DESC,e.edge_id DESC) AS rn
            FROM public.edge e JOIN public.edge_type_lu t ON t.id=e.etype_id
            WHERE ` + strings.Join(where, " AND ") + `) x
        WHERE x.rn <= $` + strconv.Itoa(len(args)) + ` ORDER BY x.owner,x.rn`
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}

	defer rows.Close()

	out := make(map[string][]*types.Edge, len(eids))
	var more []string
	for rows.Next() {
		var own, id, from, to, rn int64
		var etype, raw string
		var c, u time.Time
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

		out[key] = append(out[key], &types.Edge{ID: strconv.FormatInt(id, 10), Relation: rel,
			FromEntity: &types.Entity{ID: strconv.FormatInt(from, 10)},
			ToEntity:   &types.Entity{ID: strconv.FormatInt(to, 10)}, CreatedAt: c.UTC(), LastSeen: u.UTC()})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return out, more, nil
}
