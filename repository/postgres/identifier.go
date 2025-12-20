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
	"github.com/owasp-amass/asset-db/types"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// Params: @record::jsonb
const upsertIdentifierText = `SELECT public.identifier_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectIdentifierByID = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.id_type, a.attrs
FROM public.identifier_get_by_id(@row_id::bigint) AS a;`

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

func (r *PostgresRepository) fetchIdentifierByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.identifier.by_id",
		SQLText: selectIdentifierByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamgen.Identifier
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u,
		&a.UniqueID, &a.Type, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no identifier found")
	}
	if a.UniqueID == "" {
		return nil, errors.New("identifier unique ID is missing")
	}
	if a.Type == "" {
		return nil, fmt.Errorf("identifier type is missing")
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

	var attrs identifierAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Status = attrs.Status
	a.CreationDate = attrs.CreatedDate
	a.UpdatedDate = attrs.UpdatedDate
	a.ExpirationDate = attrs.ExpirationDate

	return e, nil
}
