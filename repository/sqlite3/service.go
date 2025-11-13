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
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: :unique_id, :service_type, :attrs
const upsertServiceText = `
INSERT INTO service(unique_id, service_type, attrs)
VALUES (:unique_id, :service_type, :attrs)
ON CONFLICT(unique_id) DO UPDATE SET
    service_type = COALESCE(excluded.service_type, service.service_type),
    attrs        = COALESCE(excluded.attrs,        service.attrs),
    updated_at   = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByServiceText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'service' LIMIT 1)
  AND natural_key = :unique_id
LIMIT 1`

// Param: :row_id
const selectServiceByIDText = `
SELECT id, created_at, updated_at, unique_id, service_type, attrs 
FROM service
WHERE id = :row_id
LIMIT 1`

type serviceAttributes struct {
	Output     string              `json:"output"`
	OutputLen  int                 `json:"output_length"`
	Attributes map[string][]string `json:"attributes"`
}

func (r *SqliteRepository) upsertService(ctx context.Context, a *oamplat.Service) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid service provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("the service does not have a unique identifier")
	}
	if a.Type == "" {
		return 0, fmt.Errorf("the service type cannot be empty")
	}

	attrs := serviceAttributes{
		Output:     a.Output,
		OutputLen:  a.OutputLen,
		Attributes: a.Attributes,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.service.upsert",
		SQLText: upsertServiceText,
		Args: []any{
			sql.Named("unique_id", a.ID),
			sql.Named("service_type", a.Type),
			sql.Named("attrs", string(attrsJSON)),
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
		Name:    "asset.service.entity_id_by_service",
		SQLText: selectEntityIDByServiceText,
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

func (r *SqliteRepository) fetchServiceByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.service.by_id",
		SQLText: selectServiceByIDText,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamplat.Service
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.ID, &a.Type, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, fmt.Errorf("no service found with row ID %d", rowID)
	}
	if a.ID == "" {
		return nil, fmt.Errorf("the service at row ID %d does not have a unique identifier", rowID)
	}
	if a.Type == "" {
		return nil, fmt.Errorf("the service at row ID %d does not have a type", rowID)
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

	var attrs serviceAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Output = attrs.Output
	a.OutputLen = attrs.OutputLen
	a.Attributes = attrs.Attributes

	return e, nil
}
