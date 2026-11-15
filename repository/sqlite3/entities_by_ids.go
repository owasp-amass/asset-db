// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	dbt "github.com/owasp-amass/asset-db/types"
)

// MaxEntitiesByIds is the most IDs FindEntitiesByIds reads at once.
const MaxEntitiesByIds = 1000

// FindEntitiesByIds returns the entities with the given IDs, with their
// assets, in the order of ids. An ID with no entity is left out. The
// entities' types and rows are read in one query, then each asset by row.
func (r *SqliteRepository) FindEntitiesByIds(ctx context.Context, ids []string) ([]*dbt.Entity, error) {
	if r == nil || r.rpool == nil {
		return nil, errors.New("missing SQLite reader")
	}
	if len(ids) > MaxEntitiesByIds {
		return nil, fmt.Errorf("at most %d entity IDs may be read at once", MaxEntitiesByIds)
	}

	args := make([]any, 0, len(ids))
	for _, id := range ids {
		eid, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid entity ID %q: %w", id, err)
		}

		args = append(args, eid)
	}
	if len(args) == 0 {
		return nil, nil
	}

	query := `SELECT e.entity_id, t.name, e.row_id FROM entity e JOIN entity_type_lu t ON t.id = e.etype_id
        WHERE e.entity_id IN (` + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + `)`
	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: fmt.Sprintf("entity.by_ids.%d", len(args)), SQLText: query,
		Args: args, Result: ch})
	var result *rowsReadResult
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result = <-ch:
	}
	if result.Err != nil {
		return nil, result.Err
	}

	type core struct {
		eid, rid int64
		etype    string
	}
	var cores []core
	for result.Rows.Next() {
		var c core
		if err := result.Rows.Scan(&c.eid, &c.etype, &c.rid); err != nil {
			_ = result.Rows.Close()
			return nil, err
		}

		cores = append(cores, c)
	}

	err := result.Rows.Err()
	_ = result.Rows.Close()
	if err != nil {
		return nil, err
	}

	found := make(map[string]*dbt.Entity, len(cores))
	for _, c := range cores {
		e, err := r.fetchEntityAssetByTableID(ctx, c.eid, normalizeType(c.etype), c.rid)
		if err != nil {
			return nil, err
		}

		found[strconv.FormatInt(c.eid, 10)] = e
	}

	out := make([]*dbt.Entity, 0, len(found))
	for _, id := range ids {
		if e, ok := found[id]; ok {
			out = append(out, e)
		}
	}

	return out, nil
}
