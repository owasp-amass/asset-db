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
const upsertFQDN = `
INSERT INTO fqdn (fqdn)
VALUES (:fqdn_text)
ON CONFLICT(fqdn) DO UPDATE SET
  updated_at = CURRENT_TIMESTAMP;`

// Param: :fqdn_text
const selectFQDNIDByFQDN = `
SELECT id FROM fqdn
WHERE fqdn = :fqdn_text;`

// Param: :fqdn_id
const selectFQDNByID = `
SELECT id, created_at, updated_at, fqdn FROM fqdn
WHERE id = :fqdn_id;`

type fqdnStatements struct {
	UpsertFQDNStmt         *sql.Stmt
	SelectFQDNIDByFQDNStmt *sql.Stmt
	SelectFQDNByIDStmt     *sql.Stmt
}

func (r *SqliteRepository) prepareFQDNStatements(ctx context.Context) error {
	var err error
	stmts := new(fqdnStatements)

	if stmts.UpsertFQDNStmt, err = r.DB.PrepareContext(ctx, upsertFQDN); err != nil {
		return err
	}
	if stmts.SelectFQDNIDByFQDNStmt, err = r.DB.PrepareContext(ctx, selectFQDNIDByFQDN); err != nil {
		return err
	}
	if stmts.SelectFQDNByIDStmt, err = r.DB.PrepareContext(ctx, selectFQDNByID); err != nil {
		return err
	}

	r.fqdnStmts = stmts
	return nil
}
func (r *SqliteRepository) closeFQDNStatements() error {
	if r.fqdnStmts == nil {
		return nil
	}
	if r.fqdnStmts.UpsertFQDNStmt != nil {
		r.fqdnStmts.UpsertFQDNStmt.Close()
	}
	if r.fqdnStmts.SelectFQDNIDByFQDNStmt != nil {
		r.fqdnStmts.SelectFQDNIDByFQDNStmt.Close()
	}
	if r.fqdnStmts.SelectFQDNByIDStmt != nil {
		r.fqdnStmts.SelectFQDNByIDStmt.Close()
	}
	return nil
}

func (r *SqliteRepository) upsertFQDN(ctx context.Context, a *oamdns.FQDN) (int64, error) {
	_ = r.fqdnStmts.UpsertFQDNStmt.QueryRowContext(ctx, sql.Named("fqdn_text", a.Name))

	row := r.fqdnStmts.SelectFQDNIDByFQDNStmt.QueryRowContext(ctx, sql.Named("fqdn_text", a.Name))

	var id int64
	return id, row.Scan(&id)
}

func (r *SqliteRepository) fetchFQDNByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	var id int64
	var fqdn string
	var c, u *string

	if err := r.fqdnStmts.SelectFQDNByIDStmt.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &fqdn); err != nil {
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
