// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
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
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'autnumrecord')
  AND display_value = :handle
LIMIT 1`

// Param: :row_id
const selectAutnumByID = `
SELECT id, created_at, updated_at, record_name, handle, asn, record_status, created_date, updated_date, whois_server
FROM autnumrecord
WHERE id = :row_id
LIMIT 1`

type autnum struct {
	ID           int64      `json:"id"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
	RecordName   *string    `json:"record_name,omitempty"`
	Handle       string     `json:"handle"`
	ASN          int64      `json:"asn"`
	RecordStatus *string    `json:"record_status,omitempty"`
	CreatedDate  *string    `json:"created_date,omitempty"`
	UpdatedDate  *string    `json:"updated_date,omitempty"`
	WhoisServer  *string    `json:"whois_server,omitempty"`
}

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
			sql.Named("record_status", a.Status),
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

	var a autnum
	var c, u *string
	if err := result.Row.Scan(&a.ID, &c, &u, &a.RecordName, &a.Handle, &a.ASN,
		&a.RecordStatus, &a.CreatedDate, &a.UpdatedDate, &a.WhoisServer); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	if a.CreatedAt == nil || a.UpdatedAt == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var cdate string
	if a.CreatedDate != nil {
		cdate = *a.CreatedDate
	}

	var udate string
	if a.UpdatedDate != nil {
		udate = *a.UpdatedDate
	}

	var rname string
	if a.RecordName != nil {
		rname = *a.RecordName
	}

	var rstatus string
	if a.RecordStatus != nil {
		rstatus = *a.RecordStatus
	}

	var whois string
	if a.WhoisServer != nil {
		whois = *a.WhoisServer
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: a.CreatedAt.In(time.UTC).Local(),
		LastSeen:  a.UpdatedAt.In(time.UTC).Local(),
		Asset: &oamreg.AutnumRecord{
			Number:      int(a.ASN),
			Handle:      a.Handle,
			Name:        rname,
			WhoisServer: whois,
			CreatedDate: cdate,
			UpdatedDate: udate,
			Status:      []string{rstatus},
		},
	}, nil
}
