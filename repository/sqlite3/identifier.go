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
    updated_at = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByIdentifierText = `
SELECT entity_id FROM entity 
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'identifier' LIMIT 1) 
  AND display_value = :unique_id 
LIMIT 1`

// Param: :row_id
const selectIdentifierByID = `
SELECT id, created_at, updated_at, id_type, unique_id 
FROM identifier 
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertIdentifier(ctx context.Context, a *oamgen.Identifier) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.identifier.upsert",
		SQLText: upsertIdentifierText,
		Args: []any{
			sql.Named("id_type", a.Type),
			sql.Named("unique_id", a.UniqueID),
		},
		Result: done,
	})
	err := <-done
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.identifier.entity_id_by_identifier",
		SQLText: selectEntityIDByIdentifierText,
		Args:    []any{sql.Named("unique_id", a.UniqueID)},
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

func (r *SqliteRepository) fetchIdentifierByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.identifier.by_id",
		SQLText: selectIdentifierByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var id int64
	var uid string
	var c, u, it *string
	if err := result.Row.Scan(&id, &c, &u, &it, &uid); err != nil {
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
