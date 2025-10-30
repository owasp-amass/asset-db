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
	"github.com/owasp-amass/open-asset-model/contact"
)

// Params: :discovered_at
const upsertContactRecord = `
INSERT INTO contactrecord(discovered_at) VALUES (lower(:discovered_at))
ON CONFLICT(discovered_at) DO UPDATE SET updated_at = CURRENT_TIMESTAMP;`

// Param: :discovered_at
const selectEntityIDByContactRecordText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'contactrecord' LIMIT 1)
  AND display_value = lower(:discovered_at)
LIMIT 1;`

// Param: :row_id
const selectContactRecordByID = `
SELECT id, created_at, updated_at, discovered_at 
FROM contactrecord 
WHERE id = :row_id 
LIMIT 1;`

func (r *SqliteRepository) upsertContactRecord(ctx context.Context, a *contact.ContactRecord) (int64, error) {
	const keySel = "asset.contact.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertContactRecord)
	if err != nil {
		return 0, err
	}
	_ = stmt.QueryRowContext(ctx, sql.Named("discovered_at", a.DiscoveredAt))

	const keySel2 = "asset.contact.entity_id_by_contact"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByContactRecordText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("discovered_at", a.DiscoveredAt)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchContactRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.contact.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectContactRecordByID)
	if err != nil {
		return nil, err
	}

	var id int64
	var c, u *string
	var disat string
	if err := st.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &disat); err != nil {
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
		Asset:     &contact.ContactRecord{DiscoveredAt: disat},
	}, nil
}
