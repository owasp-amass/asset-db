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
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Params: @record::jsonb
const upsertAutnumRecordText = `SELECT public.autnumrecord_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectAutnumByID = `
SELECT a.id, a.created_at, a.updated_at, a.record_name, a.handle, a.asn, a.whois_server, a.attrs
FROM autnumrecord_get_by_id(@row_id::bigint) AS a;`

type autnumAttributes struct {
	Raw         string   `json:"raw,omitempty"`
	Status      []string `json:"status,omitempty"`
	CreatedDate string   `json:"created_date,omitempty"`
	UpdatedDate string   `json:"updated_date,omitempty"`
}

func (r *PostgresRepository) upsertAutnumRecord(ctx context.Context, a *oamreg.AutnumRecord) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid autnum record provided")
	}
	if a.Name == "" {
		return 0, errors.New("autnum record name cannot be empty")
	}
	if a.Handle == "" {
		return 0, errors.New("autnum record handle cannot be empty")
	}
	if a.Number == 0 {
		return 0, errors.New("autnum record ASN cannot be zero")
	}
	if _, err := parseTimestamp(a.CreatedDate); err != nil {
		return 0, fmt.Errorf("autnum record must have a valid created date: %v", err)
	}
	if _, err := parseTimestamp(a.UpdatedDate); err != nil {
		return 0, fmt.Errorf("autnum record must have a valid updated date: %v", err)
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.autnum.upsert",
		SQLText: upsertAutnumRecordText,
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

func (r *PostgresRepository) fetchAutnumRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.autnum.by_id",
		SQLText: selectAutnumByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamreg.AutnumRecord
	var c, u, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &a.Name,
		&a.Handle, &a.Number, &a.WhoisServer, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no autnum record found")
	}
	if a.Name == "" {
		return nil, errors.New("autnum record name is missing")
	}
	if a.Handle == "" {
		return nil, errors.New("autnum record handle is missing")
	}
	if a.Number == 0 {
		return nil, errors.New("autnum record ASN is missing")
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

	var attrs autnumAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Raw = attrs.Raw
	a.Status = attrs.Status
	a.CreatedDate = attrs.CreatedDate
	a.UpdatedDate = attrs.UpdatedDate

	if _, err := parseTimestamp(a.CreatedDate); err != nil {
		return nil, fmt.Errorf("autnum record created date is missing or invalid: %v", err)
	}
	if _, err := parseTimestamp(a.UpdatedDate); err != nil {
		return nil, fmt.Errorf("autnum record updated date is missing or invalid: %v", err)
	}

	return e, nil
}
