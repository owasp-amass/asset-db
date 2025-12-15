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

// Params: :fqdn_text, :attrs
const upsertFQDNText = `
INSERT INTO fqdn (fqdn, attrs)
VALUES (:fqdn_text, :attrs)
ON CONFLICT(fqdn_norm) DO UPDATE SET 
	attrs      = json_patch(fqdn.attrs, excluded.attrs),
	updated_at = CURRENT_TIMESTAMP`

// Param: :fqdn_text
const selectEntityIDByFQDNText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'fqdn' LIMIT 1)
  AND natural_key = lower(:fqdn_text)
LIMIT 1`

// Param: :row_id
const selectFQDNByIDText = `
SELECT id, created_at, updated_at, fqdn, attrs
FROM fqdn
WHERE id = :row_id
LIMIT 1`

func (r *PostgresRepository) upsertFQDN(ctx context.Context, a *oamdns.FQDN) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid FQDN provided")
	}
	if a.Name == "" {
		return 0, errors.New("FQDN name cannot be empty")
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.fqdn.upsert",
		SQLText: upsertFQDNText,
		Args: []any{
			sql.Named("fqdn_text", a.Name),
			sql.Named("attrs", "{}"),
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

func (r *PostgresRepository) fetchFQDNByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
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

	var row_id int64
	var a oamdns.FQDN
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.Name, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no FQDN record found")
	}
	if a.Name == "" {
		return nil, errors.New("FQDN name is missing")
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
