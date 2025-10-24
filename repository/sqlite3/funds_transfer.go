// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// FUNDSTRANSFER --------------------------------------------------------------
// Params: :unique_id, :amount, :reference_number, :currency, :transfer_method, :exchange_date, :exchange_rate, :attrs
const tmplUpsertFundsTransfer = `
WITH
  row_try AS (
    INSERT INTO fundstransfer(unique_id, amount, reference_number, currency, transfer_method, exchange_date, exchange_rate)
    VALUES (:unique_id, :amount, :reference_number, :currency, :transfer_method, :exchange_date, :exchange_rate)
    ON CONFLICT(unique_id) DO UPDATE SET
      amount           = COALESCE(excluded.amount,           fundstransfer.amount),
      reference_number = COALESCE(excluded.reference_number, fundstransfer.reference_number),
      currency         = COALESCE(excluded.currency,         fundstransfer.currency),
      transfer_method  = COALESCE(excluded.transfer_method,  fundstransfer.transfer_method),
      exchange_date    = COALESCE(excluded.exchange_date,    fundstransfer.exchange_date),
      exchange_rate    = COALESCE(excluded.exchange_rate,    fundstransfer.exchange_rate),
      updated_at       = CASE WHEN
        (excluded.amount           IS NOT fundstransfer.amount) OR
        (excluded.reference_number IS NOT fundstransfer.reference_number) OR
        (excluded.currency         IS NOT fundstransfer.currency) OR
        (excluded.transfer_method  IS NOT fundstransfer.transfer_method) OR
        (excluded.exchange_date    IS NOT fundstransfer.exchange_date) OR
        (excluded.exchange_rate    IS NOT fundstransfer.exchange_rate)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE fundstransfer.updated_at END
    WHERE (excluded.amount           IS NOT fundstransfer.amount) OR
          (excluded.reference_number IS NOT fundstransfer.reference_number) OR
          (excluded.currency         IS NOT fundstransfer.currency) OR
          (excluded.transfer_method  IS NOT fundstransfer.transfer_method) OR
          (excluded.exchange_date    IS NOT fundstransfer.exchange_date) OR
          (excluded.exchange_rate    IS NOT fundstransfer.exchange_rate)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM fundstransfer WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('fundstransfer') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='fundstransfer' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :unique_id, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:unique_id LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'fundstransfer',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

type FundsTransfer struct {
	ID              int64      `json:"id"`
	CreatedAt       *time.Time `json:"created_at,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
	UniqueID        string     `json:"unique_id"`
	Amount          float64    `json:"amount"`
	ReferenceNumber *string    `json:"reference_number,omitempty"`
	Currency        *string    `json:"currency,omitempty"`
	TransferMethod  *string    `json:"transfer_method,omitempty"`
	ExchangeDate    *time.Time `json:"exchange_date,omitempty"`
	ExchangeRate    *float64   `json:"exchange_rate,omitempty"`
}

func (s *Statements) UpsertFundsTransfer(ctx context.Context, ft FundsTransfer) (int64, error) {
	row := s.UpsertFundsTransferStmt.QueryRowContext(ctx,
		sql.Named("unique_id", ft.UniqueID),
		sql.Named("amount", ft.Amount),
		sql.Named("reference_number", ft.ReferenceNumber),
		sql.Named("currency", ft.Currency),
		sql.Named("transfer_method", ft.TransferMethod),
		sql.Named("exchange_date", ft.ExchangeDate),
		sql.Named("exchange_rate", ft.ExchangeRate),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchFundsTransferByRowID(ctx context.Context, rowID int64) (*FundsTransfer, error) {
	query := `SELECT id, created_at, updated_at, unique_id, amount, reference_number, currency, transfer_method, exchange_date, exchange_rate
		      FROM fundstransfer WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "fundstransfer", query)
	if err != nil {
		return nil, err
	}

	var a FundsTransfer
	var c, u, ed *string
	if err := st.QueryRowContext(ctx, rowID).Scan(&a.ID, &c, &u, &a.UniqueID,
		&a.Amount, &a.ReferenceNumber, &a.Currency, &a.TransferMethod, &ed, &a.ExchangeRate,
	); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	a.ExchangeDate = parseTS(ed)
	return &a, nil
}
