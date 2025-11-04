// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: :discovered_at
const upsertContactRecord = `
INSERT INTO contactrecord(discovered_at) VALUES (:discovered_at)
ON CONFLICT(discovered_at) DO UPDATE SET updated_at = CURRENT_TIMESTAMP`

// Param: :discovered_at
const selectEntityIDByContactRecordText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'contactrecord' LIMIT 1)
  AND natural_key = :discovered_at
LIMIT 1`

// Param: :row_id
const selectContactRecordByID = `
SELECT id, created_at, updated_at, discovered_at 
FROM contactrecord 
WHERE id = :row_id 
LIMIT 1`

func (r *SqliteRepository) upsertContactRecord(ctx context.Context, a *contact.ContactRecord) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.contact.upsert",
		SQLText: upsertContactRecord,
		Args:    []any{sql.Named("discovered_at", a.DiscoveredAt)},
		Result:  done,
	})
	err := <-done
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.contact.entity_id_by_contact",
		SQLText: selectEntityIDByContactRecordText,
		Args:    []any{sql.Named("discovered_at", a.DiscoveredAt)},
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

func (r *SqliteRepository) fetchContactRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.contact.by_id",
		SQLText: selectContactRecordByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var id int64
	var c, u string
	var disat string
	if err := result.Row.Scan(&id, &c, &u, &disat); err != nil {
		return nil, err
	}

	e := &types.Entity{
		ID:    strconv.FormatInt(eid, 10),
		Asset: &contact.ContactRecord{DiscoveredAt: disat},
	}

	if created, err := parseTimestamp(c); err != nil {
		return nil, err
	} else {
		e.CreatedAt = created.In(time.UTC).Local()
	}
	if updated, err := parseTimestamp(u); err != nil {
		return nil, err
	} else {
		e.LastSeen = updated.In(time.UTC).Local()
	}

	return e, nil
}
