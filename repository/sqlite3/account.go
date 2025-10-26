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

// ACCOUNT --------------------------------------------------------------------
// Params: :unique_id, :account_type, :username, :account_number, :balance, :active, :attrs
const tmplUpsertAccount = `
WITH
  row_try AS (
    INSERT INTO account(unique_id, account_type, username, account_number, balance, active)
    VALUES (:unique_id, :account_type, :username, :account_number, :balance, :active)
    ON CONFLICT(unique_id) DO UPDATE SET
      account_type   = COALESCE(excluded.account_type,   account.account_type),
      username       = COALESCE(excluded.username,       account.username),
      account_number = COALESCE(excluded.account_number, account.account_number),
      balance        = COALESCE(excluded.balance,        account.balance),
      active         = COALESCE(excluded.active,         account.active),
      updated_at     = CASE WHEN
        (excluded.account_type   IS NOT account.account_type) OR
        (excluded.username       IS NOT account.username) OR
        (excluded.account_number IS NOT account.account_number) OR
        (excluded.balance        IS NOT account.balance) OR
        (excluded.active         IS NOT account.active)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE account.updated_at END
    WHERE (excluded.account_type   IS NOT account.account_type) OR
          (excluded.username       IS NOT account.username) OR
          (excluded.account_number IS NOT account.account_number) OR
          (excluded.balance        IS NOT account.balance) OR
          (excluded.active         IS NOT account.active)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM account WHERE unique_id = :unique_id LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('account')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (
    SELECT id FROM ensure_type
    UNION ALL SELECT id FROM entity_type_lu WHERE name='account' LIMIT 1
  ),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :unique_id, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (
    SELECT entity_id FROM ent_ins
    UNION ALL SELECT entity_id FROM entities
    WHERE type_id=(SELECT id FROM type_id) AND display_value=:unique_id LIMIT 1
  ),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id), 'account', (SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

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

func (s *Statements) UpsertAccount(ctx context.Context, a *oamacct.Account) (int64, error) {
	row := s.UpsertAccountStmt.QueryRowContext(ctx,
		sql.Named("unique_id", a.ID),
		sql.Named("account_type", a.Type),
		sql.Named("username", a.Username),
		sql.Named("account_number", a.Number),
		sql.Named("balance", a.Balance),
		sql.Named("active", a.Active),
		sql.Named("attrs", "{}"),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchAccountByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, unique_id, account_type, username, account_number, balance, active
		      FROM account WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "account", query)
	if err != nil {
		return nil, err
	}

	var a account
	var c, u *string
	var act *int64
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.UniqueID, &a.AccountType, &a.Username, &a.AccountNo, &a.Balance, &act,
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
		CreatedAt: (*a.CreatedAt).In(time.UTC).Local(),
		LastSeen:  (*a.UpdatedAt).In(time.UTC).Local(),
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
