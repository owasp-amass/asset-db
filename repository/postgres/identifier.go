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
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// Params: @record::jsonb
const upsertIdentifierText = `SELECT public.identifier_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectIdentifierByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.id_type, a.attrs
FROM public.identifier_get_by_id(@row_id::bigint) AS a;`

// Params: @filters::jsonb, @since::timestamp, @limit::integer
const selectIdentifierFindByContentText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.id_type, a.attrs 
FROM public.identifier_find_by_content(@filters::jsonb, @since::timestamp, @limit::integer) AS a;`

// Params: @since::timestamp, @limit::integer
const selectIdentifierSinceText = `
SELECT a.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.id_type, a.attrs 
FROM public.identifier_updated_since(@since::timestamp, @limit::integer) AS a;`

type identifierAttributes struct {
	Status         string `json:"status,omitempty"`
	CreatedDate    string `json:"created_date,omitempty"`
	UpdatedDate    string `json:"updated_date,omitempty"`
	ExpirationDate string `json:"expiration_date,omitempty"`
}

func (r *PostgresRepository) upsertIdentifier(ctx context.Context, a *oamgen.Identifier) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid identifier provided")
	}
	if a.UniqueID == "" {
		return 0, fmt.Errorf("identifier unique ID cannot be empty")
	}
	if a.Type == "" {
		return 0, fmt.Errorf("identifier type cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.identifier.upsert",
		SQLText: upsertIdentifierText,
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

func (r *PostgresRepository) fetchIdentifierByRowID(ctx context.Context, eid, rowID int64) (*dbt.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.identifier.by_id",
		SQLText: selectIdentifierByIDText,
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
	var a oamgen.Identifier
	if err := result.Row.Scan(&row_id, &c, &u, &a.UniqueID, &a.Type, &attrsJSON); err != nil {
		return nil, err
	}

	e, err := r.buildIdentifierEntity(eid, row_id, c, u, attrsJSON, &a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (r *PostgresRepository) findIdentifiersByContent(ctx context.Context, filters dbt.ContentFilters, since time.Time, limit int) ([]*dbt.Entity, error) {
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
		Name:    "asset.identifier.find_by_content",
		SQLText: selectIdentifierFindByContentText,
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
		var a oamgen.Identifier

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.UniqueID, &a.Type, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildIdentifierEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) getIdentifiersUpdatedSince(ctx context.Context, since time.Time, limit int) ([]*dbt.Entity, error) {
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
		Name:    "asset.identifier.updated_since",
		SQLText: selectIdentifierSinceText,
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
		var a oamgen.Identifier

		if err := result.Rows.Scan(&eid, &rid, &c, &u, &a.UniqueID, &a.Type, &attrsJSON); err != nil {
			continue
		}

		if ent, err := r.buildIdentifierEntity(eid, rid, c, u, attrsJSON, &a); err == nil {
			out = append(out, ent)
		}
	}

	return out, nil
}

func (r *PostgresRepository) buildIdentifierEntity(eid, rid int64, createdAt, updatedAt time.Time, attrsJSON string, a *oamgen.Identifier) (*dbt.Entity, error) {
	if rid == 0 {
		return nil, errors.New("no identifier found")
	}
	if a.UniqueID == "" {
		return nil, errors.New("identifier unique ID is missing")
	}
	if a.Type == "" {
		return nil, fmt.Errorf("identifier type is missing")
	}

	var attrs identifierAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Status = attrs.Status
	a.CreationDate = attrs.CreatedDate
	a.UpdatedDate = attrs.UpdatedDate
	a.ExpirationDate = attrs.ExpirationDate

	return &dbt.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: createdAt.In(time.UTC).Local(),
		LastSeen:  updatedAt.In(time.UTC).Local(),
		Asset:     a,
	}, nil
}
