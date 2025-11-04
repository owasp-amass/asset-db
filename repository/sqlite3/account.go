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
	oamacct "github.com/owasp-amass/open-asset-model/account"
)

// Params: :unique_id, :account_type, :username, :account_number, :balance, :active
const upsertAccountText = `
INSERT INTO account(unique_id, account_type, username, account_number, balance, active)
VALUES (:unique_id, :account_type, :username, :account_number, :balance, :active)
ON CONFLICT(unique_id) DO UPDATE SET
	account_type   = COALESCE(excluded.account_type,   account.account_type),
    username       = COALESCE(excluded.username,       account.username),
    account_number = COALESCE(excluded.account_number, account.account_number),
    balance        = COALESCE(excluded.balance,        account.balance),
    active         = COALESCE(excluded.active,         account.active),
    updated_at     = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByAccountText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'account' LIMIT 1)
  AND natural_key = :unique_id
LIMIT 1`

// Param: :row_id
const selectAccountByID = `
SELECT id, created_at, updated_at, unique_id, account_type, username, account_number, balance, active 
FROM account
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertAccount(ctx context.Context, a *oamacct.Account) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.account.upsert",
		SQLText: upsertAccountText,
		Args: []any{
			sql.Named("unique_id", a.ID),
			sql.Named("account_type", a.Type),
			sql.Named("username", a.Username),
			sql.Named("account_number", a.Number),
			sql.Named("balance", a.Balance),
			sql.Named("active", a.Active),
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
		Name:    "asset.account.entity_id_by_account",
		SQLText: selectEntityIDByAccountText,
		Args:    []any{sql.Named("unique_id", a.ID)},
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

func (r *SqliteRepository) fetchAccountByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.account.by_id",
		SQLText: selectAccountByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var c, u string
	var row_id int64
	var a oamacct.Account
	if err := result.Row.Scan(&row_id, &c, &u, &a.ID, &a.Type,
		&a.Username, &a.Number, &a.Balance, &a.Active); err != nil {
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
