// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Params: :domain_text, :unique_id, :record_name, :raw_record, :record_status, :punycode,
//
//	:extension, :created_date, :updated_date, :expiration_date, :whois_server
const upsertDomainRecordText = `
INSERT INTO domainrecord(domain, unique_id, record_name, raw_record, record_status, 
punycode, extension, created_date, updated_date, expiration_date, whois_server)
VALUES (lower(:domain_text), :unique_id, :record_name, :raw_record, :record_status, :punycode, 
:extension, :created_date, :updated_date, :expiration_date, :whois_server)
ON CONFLICT(domain) DO UPDATE SET
	record_name   = COALESCE(excluded.record_name,   domainrecord.record_name),
    raw_record    = COALESCE(excluded.raw_record,    domainrecord.raw_record),
    record_status = COALESCE(excluded.record_status, domainrecord.record_status),
    punycode      = COALESCE(excluded.punycode,      domainrecord.punycode),
    extension     = COALESCE(excluded.extension,     domainrecord.extension),
    created_date  = COALESCE(excluded.created_date,  domainrecord.created_date),
    updated_date  = COALESCE(excluded.updated_date,  domainrecord.updated_date),
    expiration_date = COALESCE(excluded.expiration_date, domainrecord.expiration_date),
    whois_server  = COALESCE(excluded.whois_server,  domainrecord.whois_server),
    updated_at    = CURRENT_TIMESTAMP`

// Param: :domain_text
const selectEntityIDByDomainRecordText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'domainrecord' LIMIT 1)
  AND display_value = :domain_text
LIMIT 1`

// Param: :row_id
const selectDomainRecordByID = `
SELECT id, created_at, updated_at, unique_id, raw_record, record_name, domain, 
record_status, punycode, extension, created_date, updated_date, expiration_date, whois_server 
FROM domainrecord
WHERE id = :row_id
LIMIT 1`

type domrec struct {
	ID             int64      `json:"id"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	UniqueID       *string    `json:"unique_id,omitempty"`
	RawRecord      *string    `json:"raw_record,omitempty"`
	RecordName     string     `json:"record_name"`
	Domain         string     `json:"domain"`
	RecordStatus   *string    `json:"record_status,omitempty"` // TEXT[] in PG; in SQLite we commonly keep TEXT/JSON
	Punycode       *string    `json:"punycode,omitempty"`
	Extension      *string    `json:"extension,omitempty"`
	CreatedDate    *string    `json:"created_date,omitempty"`
	UpdatedDate    *string    `json:"updated_date,omitempty"`
	ExpirationDate *string    `json:"expiration_date,omitempty"`
	WhoisServer    *string    `json:"whois_server,omitempty"`
}

func (r *SqliteRepository) upsertDomainRecord(ctx context.Context, a *oamreg.DomainRecord) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.domainrecord.upsert",
		SQLText: upsertDomainRecordText,
		Args: []any{
			sql.Named("domain_text", a.Domain),
			sql.Named("unique_id", a.ID),
			sql.Named("record_name", a.Name),
			sql.Named("raw_record", a.Raw),
			sql.Named("record_status", strings.Join(a.Status, ",")),
			sql.Named("punycode", a.Punycode),
			sql.Named("extension", a.Extension),
			sql.Named("created_date", a.CreatedDate),
			sql.Named("updated_date", a.UpdatedDate),
			sql.Named("expiration_date", a.ExpirationDate),
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
		Name:    "asset.domainrecord.entity_id_by_domain",
		SQLText: selectEntityIDByDomainRecordText,
		Args:    []any{sql.Named("domain_text", a.Domain)},
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

func (r *SqliteRepository) fetchDomainRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.domainrecord.by_id",
		SQLText: selectDomainRecordByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var a domrec
	var c, u *string
	if err := result.Row.Scan(&a.ID, &c, &u, &a.UniqueID, &a.RawRecord, &a.RecordName, &a.Domain, &a.RecordStatus,
		&a.Punycode, &a.Extension, &a.CreatedDate, &a.UpdatedDate, &a.ExpirationDate, &a.WhoisServer); err != nil {
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

	var edate string
	if a.ExpirationDate != nil {
		edate = *a.ExpirationDate
	}

	var uid string
	if a.UniqueID != nil {
		uid = *a.UniqueID
	}

	var rawrec string
	if a.RawRecord != nil {
		rawrec = *a.RawRecord
	}

	var rstatus []string
	if a.RecordStatus != nil {
		rstatus = strings.Split(*a.RecordStatus, ",")
	}

	var punny string
	if a.Punycode != nil {
		punny = *a.Punycode
	}

	var ext string
	if a.Extension != nil {
		ext = *a.Extension
	}

	var whois string
	if a.WhoisServer != nil {
		whois = *a.WhoisServer
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: a.CreatedAt.In(time.UTC).Local(),
		LastSeen:  a.UpdatedAt.In(time.UTC).Local(),
		Asset: &oamreg.DomainRecord{
			Raw:            rawrec,
			ID:             uid,
			Domain:         a.Domain,
			Punycode:       punny,
			Name:           a.RecordName,
			Extension:      ext,
			WhoisServer:    whois,
			CreatedDate:    cdate,
			UpdatedDate:    udate,
			ExpirationDate: edate,
			Status:         rstatus,
		},
	}, nil
}
