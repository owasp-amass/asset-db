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
	oamfin "github.com/owasp-amass/open-asset-model/financial"
)

// Params: :unique_id, :amount, :reference_number, :currency, :transfer_method, :exchange_date, :exchange_rate
const upsertFundsTransferText = `
INSERT INTO fundstransfer(unique_id, amount, reference_number, currency, transfer_method, exchange_date, exchange_rate)
VALUES (:unique_id, :amount, :reference_number, :currency, :transfer_method, :exchange_date, :exchange_rate)
ON CONFLICT(unique_id) DO UPDATE SET
    amount           = COALESCE(excluded.amount,           fundstransfer.amount),
    reference_number = COALESCE(excluded.reference_number, fundstransfer.reference_number),
    currency         = COALESCE(excluded.currency,         fundstransfer.currency),
    transfer_method  = COALESCE(excluded.transfer_method,  fundstransfer.transfer_method),
    exchange_date    = COALESCE(excluded.exchange_date,    fundstransfer.exchange_date),
    exchange_rate    = COALESCE(excluded.exchange_rate,    fundstransfer.exchange_rate),
    updated_at       = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByFundsTransferText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'fundstransfer' LIMIT 1)
  AND natural_key = :unique_id
LIMIT 1`

// Param: :row_id
const selectFundsTransferByID = `
SELECT id, created_at, updated_at, unique_id, amount, reference_number, currency, transfer_method, exchange_date, exchange_rate 
FROM fundstransfer 
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertFundsTransfer(ctx context.Context, a *oamfin.FundsTransfer) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.funds_transfer.upsert",
		SQLText: upsertFundsTransferText,
		Args: []any{
			sql.Named("unique_id", a.ID),
			sql.Named("amount", a.Amount),
			sql.Named("reference_number", a.ReferenceNumber),
			sql.Named("currency", a.Currency),
			sql.Named("transfer_method", a.Method),
			sql.Named("exchange_date", a.ExchangeDate),
			sql.Named("exchange_rate", a.ExchangeRate),
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
		Name:    "asset.funds_transfer.entity_id_by_funds_transfer",
		SQLText: selectEntityIDByFundsTransferText,
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

func (r *SqliteRepository) fetchFundsTransferByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.funds_transfer.by_id",
		SQLText: selectFundsTransferByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var c, u string
	var row_id int64
	var a oamfin.FundsTransfer
	if err := result.Row.Scan(&row_id, &c, &u, &a.ID, &a.Amount,
		&a.ReferenceNumber, &a.Currency, &a.Method, &a.ExchangeDate, &a.ExchangeRate); err != nil {
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
