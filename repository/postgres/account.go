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
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oamacct "github.com/owasp-amass/open-asset-model/account"
)

// Param: @record::jsonb
const upsertAccountText = `SELECT public.account_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectAccountByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.account_type, a.username, a.account_number, a.attrs 
FROM public.account_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectAccountFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.account_type, a.username, a.account_number, a.attrs 
FROM public.account_get_by_filters(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectAccountSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.account_type, a.username, a.account_number, a.attrs 
FROM public.account_updated_since(@since::timestamp, @limit::integer) AS a;`

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

	var id int64
	j := NewRowJob(ctx, upsertAccountText, pgx.NamedArgs{"record": string(record)}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.pool.Submit(j)
	return id, j.Wait()
}

func (r *PostgresRepository) fetchAccountByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	var rid int64
	var c, u time.Time
	var attrsJSON string
	var a oamacct.Account

	j := NewRowJob(ctx, selectAccountByIDText, pgx.NamedArgs{"row_id": rowID}, func(row pgx.Row) error {
		return row.Scan(&rid, &c, &u, &a.ID, &a.Type, &a.Username, &a.Number, &attrsJSON)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	e, err := r.buildAccountEntity(eid, rid, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findAccountsByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectAccountFindByContentText, pgx.NamedArgs{
		"filters": string(filtersJSON),
		"since":   ts,
		"limit":   lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamacct.Account

			if err := rows.Scan(&eid, &rid, &c, &u, &a.ID,
				&a.Type, &a.Username, &a.Number, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildAccountEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
				out = append(out, ent)
			}
		}
		return nil
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

func (r *PostgresRepository) getAccountsUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
	if since.IsZero() {
		return nil, errors.New("invalid since time provided")
	}
	if limit < 0 {
		return nil, errors.New("invalid limit provided")
	}
	lmt := zeronull.Int4(int32(limit))

	var out []*dbt.Entity
	j := NewRowsJob(ctx, selectAccountSinceText, pgx.NamedArgs{
		"since": since.UTC(),
		"limit": lmt,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid, rid int64
			var c, u time.Time
			var attrsJSON string
			var a oamacct.Account

			if err := rows.Scan(&eid, &rid, &c, &u, &a.ID,
				&a.Type, &a.Username, &a.Number, &attrsJSON); err != nil {
				continue
			}

			if ent, err := r.buildAccountEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
				out = append(out, ent)
			}
		}
		return nil
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

func (r *PostgresRepository) buildAccountEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamacct.Account) (*dbt.Entity, error) {
	if rid == 0 {
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

	var attrs accountAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Balance = attrs.Balance
	a.Active = attrs.Active

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
