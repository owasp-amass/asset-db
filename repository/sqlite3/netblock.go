// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"net/netip"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Params: :netblock_cidr, :ip_version
const upsertNetblockText = `
INSERT INTO netblock (netblock_cidr, ip_version)
VALUES (:netblock_cidr, :ip_version)
ON CONFLICT(netblock_cidr) DO UPDATE SET
  ip_version = COALESCE(excluded.ip_version, netblock.ip_version),
  updated_at = CURRENT_TIMESTAMP`

// Param: :netblock_cidr
const selectEntityIDByNetblockText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'netblock' LIMIT 1)
  AND natural_key = :netblock_cidr
LIMIT 1`

// Param: :row_id
const selectNetblockByID = `
SELECT id, created_at, updated_at, netblock_cidr, ip_version 
FROM netblock 
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertNetblock(ctx context.Context, a *oamnet.Netblock) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.netblock.upsert",
		SQLText: upsertNetblockText,
		Args: []any{
			sql.Named("netblock_cidr", a.CIDR.String()),
			sql.Named("ip_version", a.Type),
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
		Name:    "asset.netblock.entity_id_by_netblock",
		SQLText: selectEntityIDByNetblockText,
		Args:    []any{sql.Named("netblock_cidr", a.CIDR.String())},
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

func (r *SqliteRepository) fetchNetblockByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.netblock.by_id",
		SQLText: selectNetblockByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var c, u string
	var row_id int64
	var cidrstr string
	var a oamnet.Netblock
	if err := result.Row.Scan(&row_id, &c, &u, &cidrstr, &a.Type); err != nil {
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

	cidr, err := netip.ParsePrefix(cidrstr)
	if err != nil {
		return nil, err
	}
	a.CIDR = cidr

	return e, nil
}
