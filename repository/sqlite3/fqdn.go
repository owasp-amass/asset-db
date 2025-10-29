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
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// Params: :fqdn_text
const upsertFQDNText = `
INSERT INTO fqdn (fqdn)
VALUES (lower(:fqdn_text))
ON CONFLICT(fqdn_norm) DO UPDATE SET
  updated_at = CURRENT_TIMESTAMP;`

// Param: :fqdn_text
const selectEntityIDByFQDNText = `
SELECT entity_id FROM entities
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'fqdn')
  AND display_value = lower(:fqdn_text)
LIMIT 1;`

// Param: :row_id
const selectFQDNByID = `
SELECT id, created_at, updated_at, fqdn FROM fqdn
WHERE id = :row_id
LIMIT 1;`

func (r *SqliteRepository) upsertFQDN(ctx context.Context, a *oamdns.FQDN) (int64, error) {
	const keySel = "asset.fqdn.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertFQDNText)
	if err != nil {
		return 0, err
	}
	_ = stmt.QueryRowContext(ctx, sql.Named("fqdn_text", a.Name))

	const keySel2 = "asset.fqdn.entity_id_by_fqdn"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByFQDNText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("fqdn_text", a.Name)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchFQDNByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.fqdn.by_id"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, selectFQDNByID)
	if err != nil {
		return nil, err
	}

	var id int64
	var fqdn string
	var c, u *string
	if err := stmt.QueryRowContext(ctx, sql.Named("row_id", rowID)).Scan(&id, &c, &u, &fqdn); err != nil {
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
		Asset:     &oamdns.FQDN{Name: fqdn},
	}, nil
}
