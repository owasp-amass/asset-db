// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
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
  updated_at = CURRENT_TIMESTAMP;`

// Param: :netblock_cidr
const selectEntityIDByNetblockText = `
SELECT entity_id FROM entities
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'netblock')
  AND display_value = :netblock_cidr
LIMIT 1;`

// Param: :row_id
const selectNetblockByID = `
SELECT id, created_at, updated_at, netblock_cidr, ip_version 
FROM netblock 
WHERE id = :row_id
LIMIT 1;`

func (r *SqliteRepository) upsertNetblock(ctx context.Context, a *oamnet.Netblock) (int64, error) {
	const keySel = "asset.netblock.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertNetblockText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("netblock_cidr", a.CIDR.String()),
		sql.Named("ip_version", a.Type),
	)

	const keySel2 = "asset.netblock.entity_id_by_netblock"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByFQDNText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("netblock_cidr", a.CIDR.String())).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchNetblockByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.netblock.by_id"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, selectNetblockByID)
	if err != nil {
		return nil, err
	}

	var id int64
	var netstr string
	var c, u, ipver *string
	if err := stmt.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &netstr, &ipver); err != nil {
		return nil, err
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	cidr, err := netip.ParsePrefix(netstr)
	if err != nil {
		return nil, err
	}

	var version string
	if ipver != nil {
		version = *ipver
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: created.In(time.UTC).Local(),
		LastSeen:  updated.In(time.UTC).Local(),
		Asset: &oamnet.Netblock{
			CIDR: cidr,
			Type: version,
		},
	}, nil
}
