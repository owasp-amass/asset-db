// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Params: :handle, :asn, :record_name, :record_status, :created_date, :updated_date, :whois_server
const upsertAutnumRecordText = `
INSERT INTO autnumrecord(handle, asn, record_name, record_status, created_date, updated_date, whois_server)
VALUES (:handle, :asn, :record_name, :record_status, :created_date, :updated_date, :whois_server)
ON CONFLICT(handle) DO UPDATE SET
    asn           = COALESCE(excluded.asn,           autnumrecord.asn),
    record_name   = COALESCE(excluded.record_name,   autnumrecord.record_name),
    record_status = COALESCE(excluded.record_status, autnumrecord.record_status),
    created_date  = COALESCE(excluded.created_date,  autnumrecord.created_date),
    updated_date  = COALESCE(excluded.updated_date,  autnumrecord.updated_date),
    whois_server  = COALESCE(excluded.whois_server,  autnumrecord.whois_server),
    updated_at    = CURRENT_TIMESTAMP`

// Param: :handle
const selectEntityIDByAutnumText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'autnumrecord' LIMIT 1)
  AND natural_key = :handle
LIMIT 1`

// Param: :row_id
const selectAutnumByID = `
SELECT id, created_at, updated_at, record_name, handle, asn, record_status, created_date, updated_date, whois_server
FROM autnumrecord
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertAutnumRecord(ctx context.Context, a *oamreg.AutnumRecord) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.autnum.upsert",
		SQLText: upsertAutnumRecordText,
		Args: []any{
			sql.Named("handle", a.Handle),
			sql.Named("asn", a.Number),
			sql.Named("record_name", a.Name),
			sql.Named("record_status", strings.Join(a.Status, ",")),
			sql.Named("created_date", a.CreatedDate),
			sql.Named("updated_date", a.UpdatedDate),
			sql.Named("whois_server", a.WhoisServer),
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

func (r *SqliteRepository) fetchAutnumRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
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

	var c, u string
	var row_id int64
	var status string
	var a oamreg.AutnumRecord
	if err := result.Row.Scan(&row_id, &c, &u, &a.Name, &a.Handle, &a.Number,
		&status, &a.CreatedDate, &a.UpdatedDate, &a.WhoisServer); err != nil {
		return nil, err
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

	if status != "" {
		a.Status = strings.Split(status, ",")
	}

	return e, nil
}
