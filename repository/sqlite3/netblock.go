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
const upsertNetblock = `
INSERT INTO netblock (netblock_cidr, ip_version)
VALUES (:netblock_cidr, :ip_version)
ON CONFLICT(netblock_cidr) DO UPDATE SET
  ip_version = COALESCE(excluded.ip_version, netblock.ip_version),
  updated_at = CASE
    WHEN COALESCE(excluded.ip_version, netblock.ip_version) <> netblock.ip_version
    THEN CURRENT_TIMESTAMP
    ELSE netblock.updated_at
  END;`

// Param: :netblock_cidr
const selectNetblockIDByCIDR = `
SELECT id FROM netblock
WHERE netblock_cidr = :netblock_cidr;`

// Param: :netblock_id
const selectNetblockByID = `
SELECT id, created_at, updated_at, netblock_cidr, ip_version FROM netblock
WHERE id = :netblock_id;`

type netblockStatements struct {
	UpsertNetblockStmt         *sql.Stmt
	SelectNetblockIDByCIDRStmt *sql.Stmt
	SelectNetblockByIDStmt     *sql.Stmt
}

func (r *SqliteRepository) prepareNetblockStatements(ctx context.Context) error {
	var err error
	stmts := new(netblockStatements)

	if stmts.UpsertNetblockStmt, err = r.DB.PrepareContext(ctx, upsertNetblock); err != nil {
		return err
	}
	if stmts.SelectNetblockIDByCIDRStmt, err = r.DB.PrepareContext(ctx, selectNetblockIDByCIDR); err != nil {
		return err
	}
	if stmts.SelectNetblockByIDStmt, err = r.DB.PrepareContext(ctx, selectNetblockByID); err != nil {
		return err
	}

	r.netblockStmts = stmts
	return nil
}

func (r *SqliteRepository) closeNetblockStatements() error {
	if r.netblockStmts == nil {
		return nil
	}
	if r.netblockStmts.UpsertNetblockStmt != nil {
		r.netblockStmts.UpsertNetblockStmt.Close()
	}
	if r.netblockStmts.SelectNetblockIDByCIDRStmt != nil {
		r.netblockStmts.SelectNetblockIDByCIDRStmt.Close()
	}
	if r.netblockStmts.SelectNetblockByIDStmt != nil {
		r.netblockStmts.SelectNetblockByIDStmt.Close()
	}
	return nil
}

func (r *SqliteRepository) upsertNetblock(ctx context.Context, a *oamnet.Netblock) (int64, error) {
	_ = r.netblockStmts.UpsertNetblockStmt.QueryRowContext(ctx,
		sql.Named("netblock_cidr", a.CIDR.String()),
		sql.Named("ip_version", a.Type),
	)

	row := r.netblockStmts.SelectNetblockIDByCIDRStmt.QueryRowContext(ctx,
		sql.Named("netblock_cidr", a.CIDR.String()),
	)

	var id int64
	return id, row.Scan(&id)
}

func (r *SqliteRepository) fetchNetblockByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	var id int64
	var netstr string
	var c, u, ipver *string

	if err := r.netblockStmts.SelectNetblockByIDStmt.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &netstr, &ipver); err != nil {
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
		CreatedAt: (*created).In(time.UTC).Local(),
		LastSeen:  (*updated).In(time.UTC).Local(),
		Asset: &oamnet.Netblock{
			CIDR: cidr,
			Type: version,
		},
	}, nil
}
