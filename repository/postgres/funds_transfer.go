// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
)

// Params: @record::jsonb
const upsertFundsTransferText = `SELECT public.fundstransfer_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectFundsTransferByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.amount, a.reference_number, a.attrs
FROM public.fundstransfer_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectFundsTransferFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.amount, a.reference_number, a.attrs 
FROM public.fundstransfer_get_by_filters(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectFundsTransferSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.amount, a.reference_number, a.attrs 
FROM public.fundstransfer_updated_since(@since::timestamp, @limit::integer) AS a;`

type fundsTransferAttributes struct {
	Currency       string  `json:"currency,omitempty"`
	TransferMethod string  `json:"transfer_method,omitempty"`
	ExchangeDate   string  `json:"exchange_date,omitempty"`
	ExchangeRate   float64 `json:"exchange_rate,omitempty"`
}

func (r *PostgresRepository) upsertFundsTransfer(ctx context.Context, a *oamfin.FundsTransfer) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid funds transfer provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("funds transfer unique ID cannot be empty")
	}
	if a.Amount <= 0 {
		return 0, fmt.Errorf("funds transfer must have a positive amount")
	}
	if a.Currency == "" {
		return 0, fmt.Errorf("funds transfer must have a currency specified")
	}
	if _, err := parseTimestamp(a.ExchangeDate); err != nil {
		return 0, fmt.Errorf("funds transfer must have a valid exchange date: %v", err)
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.funds_transfer.upsert",
		SQLText: upsertFundsTransferText,
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

func (r *PostgresRepository) fetchFundsTransferByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.funds_transfer.by_id",
		SQLText: selectFundsTransferByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var c, u time.Time
	var attrsJSON string
	var a oamfin.FundsTransfer
	if err := result.Row.Scan(&row_id, &c, &u, &a.ID,
		&a.Amount, &a.ReferenceNumber, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildFundsTransferEntity(eid, row_id, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findFundsTransfersByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
	if !since.IsZero() {
		since = since.UTC()
	}
	ts := zeronull.Timestamp(since)

	if len(filters) == 0 {
		return nil, errors.New("no filters provided")
	}

	filtersJSON, err := json.Marshal(filters)
	if err != nil {
		return nil, err
	}

	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.funds_transfer.find_by_content",
		SQLText: selectFundsTransferFindByContentText,
		Args: pgx.NamedArgs{
			"filters": string(filtersJSON),
			"since":   ts,
			"limit":   limit,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string
		var a oamfin.FundsTransfer

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.ID,
			&a.Amount, &a.ReferenceNumber, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildFundsTransferEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getFundsTransfersUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "asset.funds_transfer.updated_since",
		SQLText: selectFundsTransferSinceText,
		Args: pgx.NamedArgs{
			"since": since.UTC(),
			"limit": lmt,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid, rid int64
		var c, u time.Time
		var attrsJSON string
		var a oamfin.FundsTransfer

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.ID,
			&a.Amount, &a.ReferenceNumber, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildFundsTransferEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildFundsTransferEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamfin.FundsTransfer) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no funds transfer found")
	}
	if a.ID == "" {
		return nil, errors.New("funds transfer unique ID is missing")
	}
	if a.Amount <= 0 {
		return nil, errors.New("funds transfer must have a positive amount")
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
		return nil, fmt.Errorf("funds transfer exchange date is missing or invalid: %v", err)
	}

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
