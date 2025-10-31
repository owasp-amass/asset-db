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
  AND display_value = :unique_id
LIMIT 1`

// Param: :row_id
const selectFundsTransferByID = `
SELECT id, created_at, updated_at, unique_id, amount, reference_number, currency, transfer_method, exchange_date, exchange_rate 
FROM fundstransfer 
WHERE id = :row_id
LIMIT 1`

type funds struct {
	ID              int64      `json:"id"`
	CreatedAt       *time.Time `json:"created_at,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
	UniqueID        string     `json:"unique_id"`
	Amount          float64    `json:"amount"`
	ReferenceNumber *string    `json:"reference_number,omitempty"`
	Currency        *string    `json:"currency,omitempty"`
	TransferMethod  *string    `json:"transfer_method,omitempty"`
	ExchangeDate    *string    `json:"exchange_date,omitempty"`
	ExchangeRate    *float64   `json:"exchange_rate,omitempty"`
}

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

	var a funds
	var c, u, ed *string
	if err := result.Row.Scan(&a.ID, &c, &u, &a.UniqueID, &a.Amount,
		&a.ReferenceNumber, &a.Currency, &a.TransferMethod, &ed, &a.ExchangeRate); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	if a.CreatedAt == nil || a.UpdatedAt == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var edate string
	if a.ExchangeDate != nil {
		edate = *a.ExchangeDate
	}

	var refnum string
	if a.ReferenceNumber != nil {
		refnum = *a.ReferenceNumber
	}

	var curr string
	if a.Currency != nil {
		curr = *a.Currency
	}

	var tmethod string
	if a.TransferMethod != nil {
		tmethod = *a.TransferMethod
	}

	var exrate float64
	if a.ExchangeRate != nil {
		exrate = *a.ExchangeRate
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: a.CreatedAt.In(time.UTC).Local(),
		LastSeen:  a.UpdatedAt.In(time.UTC).Local(),
		Asset: &oamfin.FundsTransfer{
			ID:              a.UniqueID,
			Amount:          a.Amount,
			ReferenceNumber: refnum,
			Currency:        curr,
			Method:          tmethod,
			ExchangeDate:    edate,
			ExchangeRate:    exrate,
		},
	}, nil
}
