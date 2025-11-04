// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

func (r *SqliteRepository) DeleteEntity(ctx context.Context, id string) error {
	eid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}
	return r.deleteEntityByID(ctx, eid, true)
}

// deleteEntityByID deletes a single entity and (via FK CASCADE) its incident edges
// and tag mappings. It leaves the concrete asset row intact by default; if you also
// want to remove the asset row, set alsoDeleteAsset=true.
func (r *SqliteRepository) deleteEntityByID(ctx context.Context, eid int64, alsoDeleteAsset bool) error {
	// Optionally remove the concrete asset row (requires looking up its table + row_id)
	if alsoDeleteAsset {
		const qSel = `SELECT table_name, row_id FROM entity WHERE entity_id = :entity_id LIMIT 1`
		ch := make(chan *rowReadResult, 1)
		r.rpool.Submit(&rowReadJob{
			Ctx:     ctx,
			Name:    "entity.delete.table_row_from_id",
			SQLText: qSel,
			Args:    []any{sql.Named("entity_id", eid)},
			Result:  ch,
		})

		result := <-ch
		if result.Err != nil {
			return result.Err
		}

		var t string
		var id int64
		if err := result.Row.Scan(&t, &id); err != nil {
			return err
		}

		if tbl := validateAssetTable(t); tbl != "" {
			done := make(chan error, 1)
			r.ww.Submit(&writeJob{
				Ctx:     ctx,
				Name:    "asset." + tbl + ".delete_by_id",
				SQLText: fmt.Sprintf(`DELETE FROM %s WHERE id = :row_id`, tbl),
				Args:    []any{sql.Named("row_id", id)},
				Result:  done,
			})
			if err := <-done; err != nil {
				return err
			}
		}
	}

	// Delete the entity (FKs should take care of edges, tag maps if schema has CASCADE)
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "entity.delete.by_id",
		SQLText: `DELETE FROM entity WHERE entity_id = :entity_id`,
		Args:    []any{sql.Named("entity_id", eid)},
		Result:  done,
	})
	return <-done
}
