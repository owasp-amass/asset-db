// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

func (r *SqliteRepository) DeleteEntity(ctx context.Context, id string) error {
	entityId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}
	return r.queries.DeleteEntityByID(ctx, int64(entityId), true)
}

// DeleteEntityByID deletes a single entity and (via FK CASCADE) its incident edges
// and tag mappings. It leaves the concrete asset row intact by default; if you also
// want to remove the asset row, set alsoDeleteAsset=true.
func (r *Queries) DeleteEntityByID(ctx context.Context, entityID int64, alsoDeleteAsset bool) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Optionally remove the concrete asset row (requires looking up its table + row_id)
	if alsoDeleteAsset {
		const keySel = "del.entity.refRow"
		const qSel = `SELECT table_name, row_id FROM entity_ref WHERE entity_id = ?`
		stSel, err := r.getOrPrepare(ctx, keySel, qSel)
		if err != nil {
			return err
		}
		rows, err := tx.Stmt(stSel).QueryContext(ctx, entityID)
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
			delQ := fmt.Sprintf(`DELETE FROM %s WHERE id = ?`, tbl)
			key := "del.asset." + tbl
			st, err := r.getOrPrepare(ctx, key, delQ)
			if err != nil {
				return err
			}
			if _, err := tx.Stmt(st).ExecContext(ctx, rf.rowID); err != nil {
				return err
			}
		}
	}

	// Delete the entity (FKs should take care of edges, entity_ref, tag maps if schema has CASCADE)
	const keyDel = "del.entity.byID"
	const qDel = `DELETE FROM entities WHERE entity_id = ?`
	stDel, err := r.getOrPrepare(ctx, keyDel, qDel)
	if err != nil {
		return err
	}
	res, err := tx.Stmt(stDel).ExecContext(ctx, entityID)
	if err != nil {
		return err
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// DeleteByAssetPK deletes by concrete asset primary key (table + row id).
// It removes the asset row, the entity_ref mapping, and the entity (cascading incident data).
func (r *Queries) DeleteByAssetPK(ctx context.Context, tableName string, rowID int64) error {
	tbl := validateAssetTable(tableName)
	if tbl == "" {
		return fmt.Errorf("unknown/unsupported asset table %q", tableName)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Resolve entity_id
	const keySel = "del.entityID.byAssetPK"
	const qSel = `SELECT entity_id FROM entity_ref WHERE table_name = ? AND row_id = ? LIMIT 1`
	stSel, err := r.getOrPrepare(ctx, keySel, qSel)
	if err != nil {
		return err
	}
	var eid int64
	if err := tx.Stmt(stSel).QueryRowContext(ctx, tbl, rowID).Scan(&eid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// If no mapping exists, just delete the asset row
			delQ := fmt.Sprintf(`DELETE FROM %s WHERE id = ?`, tbl)
			key := "del.asset.only." + tbl
			st, e2 := r.getOrPrepare(ctx, key, delQ)
			if e2 != nil {
				return e2
			}
			if _, e2 = tx.Stmt(st).ExecContext(ctx, rowID); e2 != nil {
				return e2
			}
			return tx.Commit()
		}
		return err
	}

	// Delete asset row first (to avoid leaving an orphan if entity delete somehow fails)
	delQ := fmt.Sprintf(`DELETE FROM %s WHERE id = ?`, tbl)
	keyDelAsset := "del.asset." + tbl
	stDelAsset, err := r.getOrPrepare(ctx, keyDelAsset, delQ)
	if err != nil {
		return err
	}
	if _, err := tx.Stmt(stDelAsset).ExecContext(ctx, rowID); err != nil {
		return err
	}

	// Delete the entity (will cascade to entity_ref, edges, and tag maps if CASCADE is enabled)
	const keyDelEnt = "del.entity.byID"
	const qDelEnt = `DELETE FROM entities WHERE entity_id = ?`
	stDelEnt, err := r.getOrPrepare(ctx, keyDelEnt, qDelEnt)
	if err != nil {
		return err
	}
	if _, err := tx.Stmt(stDelEnt).ExecContext(ctx, eid); err != nil {
		return err
	}

	return tx.Commit()
}
