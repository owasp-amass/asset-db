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
  AND display_value = :unique_id
LIMIT 1`

// Param: :row_id
const selectAccountByID = `
SELECT id, created_at, updated_at, unique_id, account_type, username, account_number, balance, active 
FROM account
WHERE id = :row_id
LIMIT 1`

type account struct {
	ID          int64      `json:"id"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	UniqueID    string     `json:"unique_id"`
	AccountType string     `json:"account_type"`
	Username    *string    `json:"username,omitempty"`
	AccountNo   *string    `json:"account_number,omitempty"`
	Balance     *float64   `json:"balance,omitempty"`
	Active      *bool      `json:"active,omitempty"`
}

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

	var a account
	var c, u *string
	var act *int64
	if err := result.Row.Scan(&a.ID, &c, &u, &a.UniqueID,
		&a.AccountType, &a.Username, &a.AccountNo, &a.Balance, &act,
	); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	if a.CreatedAt == nil || a.UpdatedAt == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var username string
	if a.Username != nil {
		username = *a.Username
	}

	var acctnum string
	if a.AccountNo != nil {
		acctnum = *a.AccountNo
	}

	var balance float64
	if a.Balance != nil {
		balance = *a.Balance
	}

	var active bool
	if act != nil {
		b := *act != 0
		active = b
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: a.CreatedAt.In(time.UTC).Local(),
		LastSeen:  a.UpdatedAt.In(time.UTC).Local(),
		Asset: &oamacct.Account{
			ID:       a.UniqueID,
			Type:     a.AccountType,
			Username: username,
			Number:   acctnum,
			Balance:  balance,
			Active:   active,
		},
	}, nil
}
