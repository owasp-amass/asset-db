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
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: @record::jsonb
const upsertServiceText = `SELECT public.service_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectServiceByIDText = `
SELECT a.id, a.created_at, a.updated_at, a.unique_id, a.service_type, a.attrs
FROM public.service_get_by_id(@row_id::bigint) AS a;`

type serviceAttributes struct {
	Output     string              `json:"output,omitempty"`
	OutputLen  int                 `json:"output_length,omitempty"`
	Attributes map[string][]string `json:"attributes,omitempty"`
}

func (r *PostgresRepository) upsertService(ctx context.Context, a *oamplat.Service) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid service provided")
	}
	if a.ID == "" {
		return 0, fmt.Errorf("the service does not have a unique identifier")
	}
	if a.Type == "" {
		return 0, fmt.Errorf("the service type cannot be empty")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.service.upsert",
		SQLText: upsertServiceText,
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

func (r *PostgresRepository) fetchServiceByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.service.by_id",
		SQLText: selectServiceByIDText,
		Args:    pgx.NamedArgs{"row_id": rowID},
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
