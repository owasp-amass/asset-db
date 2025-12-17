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
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Params: :handle, :asn, :record_name, :whois_server, :attrs
const upsertAutnumRecordText = `
INSERT INTO autnumrecord(handle, asn, record_name, whois_server, attrs)
VALUES (:handle, :asn, :record_name, :whois_server, :attrs)
ON CONFLICT(handle) DO UPDATE SET
    asn           = COALESCE(excluded.asn,           autnumrecord.asn),
    record_name   = COALESCE(excluded.record_name,   autnumrecord.record_name),
    whois_server  = COALESCE(excluded.whois_server,  autnumrecord.whois_server),
	attrs         = json_patch(autnumrecord.attrs,   excluded.attrs),
    updated_at    = CURRENT_TIMESTAMP`

// Param: :handle
const selectEntityIDByAutnumText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'autnumrecord' LIMIT 1)
  AND natural_key = :handle
LIMIT 1`

// Param: :row_id
const selectAutnumByID = `
SELECT id, created_at, updated_at, record_name, handle, asn, whois_server, attrs
FROM autnumrecord
WHERE id = :row_id
LIMIT 1`

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

	attrs := autnumAttributes{
		Raw:         a.Raw,
		Status:      a.Status,
		CreatedDate: a.CreatedDate,
		UpdatedDate: a.UpdatedDate,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.autnum.upsert",
		SQLText: upsertAutnumRecordText,
		Args: []any{
			sql.Named("handle", a.Handle),
			sql.Named("asn", a.Number),
			sql.Named("record_name", a.Name),
			sql.Named("whois_server", a.WhoisServer),
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
		Name:    "asset.autnum.entity_id_by_autnum",
		SQLText: selectEntityIDByAutnumText,
		Args:    []any{sql.Named("handle", a.Handle)},
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
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.autnum.by_id",
		SQLText: selectAutnumByID,
		Args:    []any{sql.Named("row_id", rowID)},
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
