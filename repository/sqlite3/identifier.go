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
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// Params: :id_type, :unique_id
const upsertIdentifierText = `
INSERT INTO identifier(id_type, unique_id) 
VALUES (:id_type, :unique_id) 
ON CONFLICT(unique_id) DO UPDATE SET
    id_type   = COALESCE(excluded.id_type, identifier.id_type),
    updated_at = CURRENT_TIMESTAMP;`

// Param: :unique_id
const selectEntityIDByIdentifierText = `
SELECT entity_id FROM entities
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'identifier')
  AND display_value = :unique_id
LIMIT 1;`

// Param: :row_id
const selectIdentifierByID = `
SELECT id, created_at, updated_at, id_type, unique_id 
FROM identifier
WHERE id = :row_id
LIMIT 1;`

func (r *SqliteRepository) upsertIdentifier(ctx context.Context, a *oamgen.Identifier) (int64, error) {
	const keySel = "asset.identifier.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertIdentifierText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("id_type", a.Type),
		sql.Named("unique_id", a.UniqueID),
	)

	const keySel2 = "asset.identifier.entity_id_by_identifier"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByIdentifierText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("unique_id", a.UniqueID)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchIdentifierByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.identifier.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectIdentifierByID)
	if err != nil {
		return nil, err
	}

	var id int64
	var uid string
	var c, u, it *string
	if err := st.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &it, &uid); err != nil {
		return nil, err
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var idType string
	if it != nil {
		idType = *it
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: created.In(time.UTC).Local(),
		LastSeen:  updated.In(time.UTC).Local(),
		Asset: &oamgen.Identifier{
			UniqueID: uid,
			Type:     idType,
		},
	}, nil
}
