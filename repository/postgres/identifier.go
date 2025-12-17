// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/owasp-amass/asset-db/types"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// Params: :unique_id, :id_type, :attrs
const upsertIdentifierText = `
INSERT INTO identifier(unique_id, id_type, attrs) 
VALUES (:unique_id, :id_type, :attrs) 
ON CONFLICT(unique_id) DO UPDATE SET
    id_type    = COALESCE(excluded.id_type,   identifier.id_type),
	attrs      = json_patch(identifier.attrs, excluded.attrs),
    updated_at = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByIdentifierText = `
SELECT entity_id FROM entity 
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'identifier' LIMIT 1) 
  AND natural_key = :unique_id 
LIMIT 1`

// Param: :row_id
const selectIdentifierByID = `
SELECT id, created_at, updated_at, unique_id, id_type, attrs
FROM identifier 
WHERE id = :row_id
LIMIT 1`

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

	attrs := identifierAttributes{
		Status:         a.Status,
		CreatedDate:    a.CreationDate,
		UpdatedDate:    a.UpdatedDate,
		ExpirationDate: a.ExpirationDate,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.identifier.upsert",
		SQLText: upsertIdentifierText,
		Args: []any{
			sql.Named("unique_id", a.UniqueID),
			sql.Named("id_type", a.Type),
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
		Name:    "asset.identifier.entity_id_by_identifier",
		SQLText: selectEntityIDByIdentifierText,
		Args:    []any{sql.Named("unique_id", a.UniqueID)},
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
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.identifier.by_id",
		SQLText: selectIdentifierByID,
		Args:    []any{sql.Named("row_id", rowID)},
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
