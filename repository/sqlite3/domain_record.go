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

// Params: :domain_text, :unique_id, :record_name, :raw_record, :record_status, :punycode,
//
//	:extension, :created_date, :updated_date, :expiration_date, :whois_server
const upsertDomainRecordText = `
INSERT INTO domainrecord(domain, unique_id, record_name, raw_record, record_status, 
punycode, extension, created_date, updated_date, expiration_date, whois_server)
VALUES (:domain_text, :unique_id, :record_name, :raw_record, :record_status, :punycode, 
:extension, :created_date, :updated_date, :expiration_date, :whois_server)
ON CONFLICT(:unique_id) DO UPDATE SET
	record_name   = COALESCE(excluded.record_name,   domainrecord.record_name),
    raw_record    = COALESCE(excluded.raw_record,    domainrecord.raw_record),
    record_status = COALESCE(excluded.record_status, domainrecord.record_status),
    punycode      = COALESCE(excluded.punycode,      domainrecord.punycode),
    extension     = COALESCE(excluded.extension,     domainrecord.extension),
    created_date  = COALESCE(excluded.created_date,  domainrecord.created_date),
    updated_date  = COALESCE(excluded.updated_date,  domainrecord.updated_date),
    expiration_date = COALESCE(excluded.expiration_date, domainrecord.expiration_date),
    whois_server  = COALESCE(excluded.whois_server,  domainrecord.whois_server),
    updated_at    = CURRENT_TIMESTAMP;`

// Param: :unique_id
const selectEntityIDByDomainRecordText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'domainrecord' LIMIT 1)
  AND display_value = :unique_id
LIMIT 1;`

// Param: :row_id
const selectDomainRecordByID = `
SELECT id, created_at, updated_at, unique_id, raw_record, record_name, domain, 
record_status, punycode, extension, created_date, updated_date, expiration_date, whois_server 
FROM domainrecord
WHERE id = :row_id
LIMIT 1;`

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
	const keySel = "asset.domainrecord.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertDomainRecordText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("domain_text", a.Domain),
		sql.Named("unique_id", a.ID),
		sql.Named("record_name", a.Name),
		sql.Named("raw_record", a.Raw),
		sql.Named("record_status", a.Status),
		sql.Named("punycode", a.Punycode),
		sql.Named("extension", a.Extension),
		sql.Named("created_date", a.CreatedDate),
		sql.Named("updated_date", a.UpdatedDate),
		sql.Named("expiration_date", a.ExpirationDate),
		sql.Named("whois_server", a.WhoisServer),
	)

	const keySel2 = "asset.domainrecord.entity_id_by_domain"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByDomainRecordText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("unique_id", a.ID)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchDomainRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.domainrecord.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectDomainRecordByID)
	if err != nil {
		return nil, err
	}

	var a domrec
	var c, u *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.UniqueID, &a.RawRecord, &a.RecordName,
		&a.Domain, &a.RecordStatus, &a.Punycode, &a.Extension,
		&a.CreatedDate, &a.UpdatedDate, &a.ExpirationDate, &a.WhoisServer,
	); err != nil {
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

	var rstatus string
	if a.RecordStatus != nil {
		rstatus = *a.RecordStatus
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
			Status:         []string{rstatus},
		},
	}, nil
}
