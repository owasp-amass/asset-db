// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: :unique_id, :service_type, :output_data, :output_length, :attributes
const upsertServiceText = `
INSERT INTO service(unique_id, service_type, output_data, output_length, attributes)
VALUES (:unique_id, :service_type, :output_data, :output_length, :attributes)
ON CONFLICT(unique_id) DO UPDATE SET
    service_type = COALESCE(excluded.service_type, service.service_type),
    output_data  = COALESCE(excluded.output_data,  service.output_data),
    output_length= COALESCE(excluded.output_length,service.output_length),
    attributes   = COALESCE(excluded.attributes,   service.attributes),
    updated_at   = CURRENT_TIMESTAMP`

// Param: :unique_id
const selectEntityIDByServiceText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'service' LIMIT 1)
  AND display_value = :unique_id
LIMIT 1`

// Param: :row_id
const selectServiceByIDText = `
SELECT id, created_at, updated_at, unique_id, service_type, output_data, output_length, attributes 
FROM service
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertService(ctx context.Context, a *oamplat.Service) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.service.upsert",
		SQLText: upsertServiceText,
		Args: []any{
			sql.Named("unique_id", a.ID),
			sql.Named("service_type", a.Type),
			sql.Named("output_data", a.Output),
			sql.Named("output_length", a.OutputLen),
			sql.Named("attributes", a.Attributes),
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

	var id int64
	var c, u *string
	var outLen *int64
	var uid, stype string
	var outdata, attrsStr *string
	if err := result.Row.Scan(&id, &c, &u, &uid,
		&stype, &outdata, &outLen, &attrsStr); err != nil {
		return nil, err
	}

	var attributes json.RawMessage
	if attrsStr != nil && strings.TrimSpace(*attrsStr) != "" {
		raw := json.RawMessage(*attrsStr)
		attributes = raw
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var olen int
	if outLen != nil {
		olen = int(*outLen)
	}

	var odata string
	if outdata != nil {
		odata = *outdata
	}

	var sattrs map[string][]string
	if attributes != nil {
		if err := json.Unmarshal(attributes, &sattrs); err != nil {
			return nil, err
		}
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: created.In(time.UTC).Local(),
		LastSeen:  updated.In(time.UTC).Local(),
		Asset: &oamplat.Service{
			ID:         uid,
			Type:       stype,
			Output:     odata,
			OutputLen:  olen,
			Attributes: sattrs,
		},
	}, nil
}
