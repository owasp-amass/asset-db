// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
)

// Params: :unique_id, :amount, :reference_number, :attrs
const upsertFundsTransferText = `
INSERT INTO fundstransfer(unique_id, amount, reference_number, attrs)
VALUES (:unique_id, :amount, :reference_number, :currency, :transfer_method, :exchange_date, :exchange_rate)
ON CONFLICT(unique_id) DO UPDATE SET
    amount           = COALESCE(excluded.amount,           fundstransfer.amount),
    reference_number = COALESCE(excluded.reference_number, fundstransfer.reference_number),
    attrs            = COALESCE(excluded.attrs,            fundstransfer.attrs),
    updated_at       = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByFundsTransferText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'fundstransfer' LIMIT 1)
  AND natural_key = :unique_id
LIMIT 1`

// Param: :row_id
const selectFundsTransferByID = `
SELECT id, created_at, updated_at, unique_id, amount, reference_number, attrs
FROM fundstransfer 
WHERE id = :row_id
LIMIT 1`

type fundsTransferAttributes struct {
	Currency       string  `json:"currency"`
	TransferMethod string  `json:"transfer_method"`
	ExchangeDate   string  `json:"exchange_date"`
	ExchangeRate   float64 `json:"exchange_rate"`
}

func (r *SqliteRepository) upsertFundsTransfer(ctx context.Context, a *oamfin.FundsTransfer) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid funds transfer provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("funds transfer unique ID missing")
	}
	if a.Amount <= 0 {
		return 0, fmt.Errorf("funds transfer must have a positive amount")
	}
	if a.Currency == "" {
		return 0, fmt.Errorf("funds transfer must have a currency specified")
	}
	if _, err := parseTimestamp(a.ExchangeDate); err != nil {
		return 0, fmt.Errorf("domain record must have a valid exchange date: %v", err)
	}

	attrs := fundsTransferAttributes{
		Currency:       a.Currency,
		TransferMethod: a.Method,
		ExchangeDate:   a.ExchangeDate,
		ExchangeRate:   a.ExchangeRate,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.funds_transfer.upsert",
		SQLText: upsertFundsTransferText,
		Args: []any{
			sql.Named("unique_id", a.ID),
			sql.Named("amount", a.Amount),
			sql.Named("reference_number", a.ReferenceNumber),
			sql.Named("attrs", attrsJSON),
		},
		Result: done,
	})
	err = <-done
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

	var row_id int64
	var a oamfin.FundsTransfer
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.ID,
		&a.Amount, &a.ReferenceNumber, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no funds transfer found")
	}
	if a.ID == "" {
		return nil, errors.New("funds transfer unique ID is missing")
	}
	if a.Amount <= 0 {
		return nil, errors.New("funds transfer must have a positive amount")
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

	var attrs fundsTransferAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Currency = attrs.Currency
	a.Method = attrs.TransferMethod
	a.ExchangeDate = attrs.ExchangeDate
	a.ExchangeRate = attrs.ExchangeRate

	if a.Currency == "" {
		return nil, errors.New("funds transfer currency is missing")
	}
	if _, err := parseTimestamp(a.ExchangeDate); err != nil {
		return nil, fmt.Errorf("domain record exchange date is missing or invalid: %v", err)
	}

	return e, nil
}
