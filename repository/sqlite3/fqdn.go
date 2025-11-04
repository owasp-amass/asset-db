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
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// Params: :fqdn_text
const upsertFQDNText = `
INSERT INTO fqdn (fqdn)
VALUES (lower(:fqdn_text))
ON CONFLICT(fqdn_norm) DO UPDATE SET updated_at = CURRENT_TIMESTAMP`

// Param: :fqdn_text
const selectEntityIDByFQDNText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'fqdn' LIMIT 1)
  AND natural_key = lower(:fqdn_text)
LIMIT 1`

// Param: :row_id
const selectFQDNByIDText = `
SELECT id, created_at, updated_at, fqdn 
FROM fqdn
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertFQDN(ctx context.Context, a *oamdns.FQDN) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.fqdn.upsert",
		SQLText: upsertFQDNText,
		Args:    []any{sql.Named("fqdn_text", a.Name)},
		Result:  done,
	})
	err := <-done
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.fqdn.entity_id_by_fqdn",
		SQLText: selectEntityIDByFQDNText,
		Args:    []any{sql.Named("fqdn_text", a.Name)},
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

func (r *SqliteRepository) fetchFQDNByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.fqdn.by_id",
		SQLText: selectFQDNByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var c, u string
	var row_id int64
	var a oamdns.FQDN
	if err := result.Row.Scan(&row_id, &c, &u, &a.Name); err != nil {
		return nil, err
	}

	e := &types.Entity{ID: strconv.FormatInt(eid, 10), Asset: &a}
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
