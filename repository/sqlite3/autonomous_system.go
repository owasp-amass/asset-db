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
ON CONFLICT(asn) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;`

// Param: :asn
const selectEntityIDByAutonomousSystemText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name='autonomoussystem' LIMIT 1)
  AND display_value = CAST(:asn AS TEXT) 
LIMIT 1;`

// Param: :row_id
const selectAutonomousSystemByID = `
SELECT id, created_at, updated_at, asn 
FROM autonomoussystem
WHERE id = :row_id
LIMIT 1;`

func (r *SqliteRepository) upsertAutonomousSystem(ctx context.Context, a *oamnet.AutonomousSystem) (int64, error) {
	const keySel = "asset.autonomous_system.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertAutonomousSystemText)
	if err != nil {
		return 0, err
	}
	_ = stmt.QueryRowContext(ctx, sql.Named("asn", a.Number))

	const keySel2 = "asset.autonomous_system.entity_id_by_asn"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByAutonomousSystemText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("asn", a.Number)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchAutonomousSystemByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.autonomous_system.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectAutonomousSystemByID)
	if err != nil {
		return nil, err
	}

	var c, u *string
	var id, asn int64
	if err := st.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &asn); err != nil {
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
