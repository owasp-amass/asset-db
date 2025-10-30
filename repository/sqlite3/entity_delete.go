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
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Optionally remove the concrete asset row (requires looking up its table + row_id)
	if alsoDeleteAsset {
		const keySel = "del.entity.refRow"
		const qSel = `SELECT table_name, row_id FROM entity_ref WHERE entity_id = ? ;`
		stSel, err := r.queries.getOrPrepare(ctx, keySel, qSel)
		if err != nil {
			return err
		}
		rows, err := tx.Stmt(stSel).QueryContext(ctx, eid)
		if err != nil {
			return err
		}
		type ref struct {
			table string
			rowID int64
		}
		var refs []ref
		for rows.Next() {
			var t string
			var id int64
			if err := rows.Scan(&t, &id); err != nil {
				_ = rows.Close()
				return err
			}
			refs = append(refs, ref{table: t, rowID: id})
		}
		_ = rows.Close()

		for _, rf := range refs {
			tbl := validateAssetTable(rf.table)
			if tbl == "" {
				// unknown table: skip instead of failing the whole deletion
				continue
			}
			delQ := fmt.Sprintf(`DELETE FROM %s WHERE id = ? ;`, tbl)
			key := "del.asset." + tbl
			st, err := r.queries.getOrPrepare(ctx, key, delQ)
			if err != nil {
				return err
			}
			if _, err := tx.Stmt(st).ExecContext(ctx, rf.rowID); err != nil {
				return err
			}
		}
	}

	// Delete the entity (FKs should take care of edges, entity_ref, tag maps if schema has CASCADE)
	const keyDel = "del.entity.by_id"
	const qDel = `DELETE FROM entity WHERE entity_id = ? ;`
	stDel, err := r.queries.getOrPrepare(ctx, keyDel, qDel)
	if err != nil {
		return err
	}
	res, err := tx.Stmt(stDel).ExecContext(ctx, eid)
	if err != nil {
		return err
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}
