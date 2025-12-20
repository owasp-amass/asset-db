// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/owasp-amass/asset-db/types"
	oamacct "github.com/owasp-amass/open-asset-model/account"
)

// Params: @record::jsonb
const upsertAccountText = `SELECT public.account_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectAccountByID = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.account_type, a.username, a.account_number, a.attrs 
FROM public.account_get_by_id(@row_id::bigint) AS a;`

type accountAttributes struct {
	Balance float64 `json:"balance"`
	Active  bool    `json:"active"`
}

func (r *PostgresRepository) upsertAccount(ctx context.Context, a *oamacct.Account) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid account provided")
	}
	if a.ID == "" {
		return 0, errors.New("account unique ID cannot be empty")
	}
	if a.Type == "" {
		return 0, errors.New("account type cannot be empty")
	}
	if a.Username == "" && a.Number == "" {
		return 0, errors.New("account must have either a username or account number")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.account.upsert",
		SQLText: upsertAccountText,
		Args:    pgx.NamedArgs{"record": string(record)},
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

func (r *PostgresRepository) fetchAccountByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.account.by_id",
		SQLText: selectAccountByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamacct.Account
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.ID,
		&a.Type, &a.Username, &a.Number, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no account record found")
	}
	if a.ID == "" {
		return nil, errors.New("account unique ID is missing")
	}
	if a.Type == "" {
		return nil, errors.New("account type is missing")
	}
	if a.Username == "" && a.Number == "" {
		return nil, errors.New("account must have either a username or account number")
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

	var attrs accountAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Balance = attrs.Balance
	a.Active = attrs.Active

	return e, nil
}
