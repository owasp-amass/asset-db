// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Params: :asn
const upsertAutonomousSystemText = `
INSERT INTO autonomoussystem(asn) VALUES (:asn)
ON CONFLICT(asn) DO UPDATE SET updated_at = CURRENT_TIMESTAMP`

// Param: :asn
const selectEntityIDByAutonomousSystemText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name='autonomoussystem' LIMIT 1)
  AND display_value = CAST(:asn AS TEXT) 
LIMIT 1`

// Param: :row_id
const selectAutonomousSystemByID = `
SELECT id, created_at, updated_at, asn 
FROM autonomoussystem
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertAutonomousSystem(ctx context.Context, a *oamnet.AutonomousSystem) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.autonomous_system.upsert",
		SQLText: upsertAutonomousSystemText,
		Args:    []any{sql.Named("asn", a.Number)},
		Result:  done,
	})
	err := <-done
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.autonomous_system.entity_id_by_asn",
		SQLText: selectEntityIDByAutonomousSystemText,
		Args:    []any{sql.Named("asn", a.Number)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return 0, result.Err
	}

	var id int64
	if err := result.Row.Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchAutonomousSystemByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.autonomous_system.by_id",
		SQLText: selectAutonomousSystemByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var c, u *string
	var id, asn int64
	if err := result.Row.Scan(&id, &c, &u, &asn); err != nil {
		return nil, err
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: created.In(time.UTC).Local(),
		LastSeen:  updated.In(time.UTC).Local(),
		Asset:     &oamnet.AutonomousSystem{Number: int(asn)},
	}, nil
}
