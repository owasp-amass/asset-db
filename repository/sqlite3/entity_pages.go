// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// EntitiesPage implements repository.EntityPager: one keyset page of the
// entities of atype, ordered by entity_id ascending.
func (r *SqliteRepository) EntitiesPage(ctx context.Context, atype oam.AssetType, since time.Time,
	after *types.EntityCursor, limit int) ([]*types.Entity, *types.EntityCursor, error) {
	if r == nil || r.rpool == nil {
		return nil, nil, errors.New("missing SQLite reader")
	}
	if limit < 1 || limit > 1000 {
		return nil, nil, errors.New("entity limit must be 1..1000")
	}

	args := []any{normalizeType(string(atype))}
	query := `SELECT e.entity_id FROM entity e
        JOIN entity_type_lu t ON t.id = e.etype_id
        WHERE t.name = ?`
	if !since.IsZero() {
		query += " AND e.updated_at >= ?"
		args = append(args, since.UTC())
	}
	if after != nil {
		last, err := strconv.ParseInt(after.EntityID, 10, 64)
		if err != nil {
			return nil, nil, errors.New("invalid entity cursor")
		}

		query += " AND e.entity_id > ?"
		args = append(args, last)
	}

	query += " ORDER BY e.entity_id LIMIT ?"
	args = append(args, limit)

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

	var ids []string
	rows := result.Rows
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}

		ids = append(ids, strconv.FormatInt(id, 10))
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, nil, err
	}
	_ = rows.Close()

	if len(ids) == 0 {
		return nil, nil, nil
	}

	ents, err := r.FindEntitiesByIds(ctx, ids)
	if err != nil {
		return nil, nil, err
	}

	byID := make(map[string]*types.Entity, len(ents))
	for _, e := range ents {
		byID[e.ID] = e
	}

	out := make([]*types.Entity, 0, len(ids))
	for _, id := range ids {
		if e, ok := byID[id]; ok {
			out = append(out, e)
		}
	}

	var next *types.EntityCursor
	if len(ids) == limit {
		next = &types.EntityCursor{EntityID: ids[len(ids)-1]}
	}

	return out, next, nil
}
