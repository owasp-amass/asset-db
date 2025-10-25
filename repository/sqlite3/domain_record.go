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

// DOMAINRECORD ---------------------------------------------------------------
// Params: :domain_text, :record_name, :raw_record, :record_status, :punycode, :extension,
//
//	:created_date, :updated_date, :expiration_date, :whois_server, :attrs
const tmplUpsertDomainRecord = `
WITH
  row_try AS (
    INSERT INTO domainrecord(domain, record_name, raw_record, record_status, punycode, extension,
                             created_date, updated_date, expiration_date, whois_server)
    VALUES (:domain_text, :record_name, :raw_record, :record_status, :punycode, :extension,
            :created_date, :updated_date, :expiration_date, :whois_server)
    ON CONFLICT(domain_norm) DO UPDATE SET
      record_name   = COALESCE(excluded.record_name,   domainrecord.record_name),
      raw_record    = COALESCE(excluded.raw_record,    domainrecord.raw_record),
      record_status = COALESCE(excluded.record_status, domainrecord.record_status),
      punycode      = COALESCE(excluded.punycode,      domainrecord.punycode),
      extension     = COALESCE(excluded.extension,     domainrecord.extension),
      created_date  = COALESCE(excluded.created_date,  domainrecord.created_date),
      updated_date  = COALESCE(excluded.updated_date,  domainrecord.updated_date),
      expiration_date = COALESCE(excluded.expiration_date, domainrecord.expiration_date),
      whois_server  = COALESCE(excluded.whois_server,  domainrecord.whois_server),
      updated_at    = CASE WHEN
         (excluded.record_name   IS NOT domainrecord.record_name) OR
         (excluded.raw_record    IS NOT domainrecord.raw_record) OR
         (excluded.record_status IS NOT domainrecord.record_status) OR
         (excluded.punycode      IS NOT domainrecord.punycode) OR
         (excluded.extension     IS NOT domainrecord.extension) OR
         (excluded.created_date  IS NOT domainrecord.created_date) OR
         (excluded.updated_date  IS NOT domainrecord.updated_date) OR
         (excluded.expiration_date IS NOT domainrecord.expiration_date) OR
         (excluded.whois_server  IS NOT domainrecord.whois_server)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE domainrecord.updated_at END
    WHERE (excluded.record_name   IS NOT domainrecord.record_name) OR
          (excluded.raw_record    IS NOT domainrecord.raw_record) OR
          (excluded.record_status IS NOT domainrecord.record_status) OR
          (excluded.punycode      IS NOT domainrecord.punycode) OR
          (excluded.extension     IS NOT domainrecord.extension) OR
          (excluded.created_date  IS NOT domainrecord.created_date) OR
          (excluded.updated_date  IS NOT domainrecord.updated_date) OR
          (excluded.expiration_date IS NOT domainrecord.expiration_date) OR
          (excluded.whois_server  IS NOT domainrecord.whois_server)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM domainrecord WHERE domain_norm = lower(:domain_text) LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('domainrecord')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (
    SELECT id FROM ensure_type
    UNION ALL SELECT id FROM entity_type_lu WHERE name='domainrecord' LIMIT 1
  ),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), lower(:domain_text), coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}'))
        ELSE entities.attrs
      END,
      updated_at = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now')
        ELSE entities.updated_at
      END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (
    SELECT entity_id FROM ent_ins
    UNION ALL
    SELECT entity_id FROM entities
    WHERE type_id = (SELECT id FROM type_id) AND display_value = lower(:domain_text)
    LIMIT 1
  ),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id), 'domainrecord', (SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name, row_id) DO UPDATE SET
      entity_id  = excluded.entity_id,
      updated_at = strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

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
	CreatedDate    *time.Time `json:"created_date,omitempty"`
	UpdatedDate    *time.Time `json:"updated_date,omitempty"`
	ExpirationDate *time.Time `json:"expiration_date,omitempty"`
	WhoisServer    *string    `json:"whois_server,omitempty"`
}

func (s *Statements) UpsertDomainRecord(ctx context.Context, a *oamreg.DomainRecord) (int64, error) {
	row := s.UpsertDomainRecordStmt.QueryRowContext(ctx,
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
		sql.Named("attrs", ""),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchDomainRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, unique_id, raw_record, record_name, domain, 
			  record_status, punycode, extension, created_date, updated_date, expiration_date, whois_server
		      FROM domainrecord WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "domainrecord", query)
	if err != nil {
		return nil, err
	}

	var a domrec
	var c, u, cd, ud, ex *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.UniqueID, &a.RawRecord, &a.RecordName, &a.Domain,
		&a.RecordStatus, &a.Punycode, &a.Extension, &cd, &ud, &ex, &a.WhoisServer,
	); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	if a.CreatedAt == nil || a.UpdatedAt == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var cdate time.Time
	if a.CreatedDate = parseTS(cd); a.CreatedDate != nil {
		cdate = *a.CreatedDate
	}

	var udate time.Time
	if a.UpdatedDate = parseTS(ud); a.UpdatedDate != nil {
		udate = *a.UpdatedDate
	}

	var edate time.Time
	if a.ExpirationDate = parseTS(ud); a.ExpirationDate != nil {
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
		CreatedAt: (*a.CreatedAt).In(time.UTC).Local(),
		LastSeen:  (*a.UpdatedAt).In(time.UTC).Local(),
		Asset: &oamreg.DomainRecord{
			Raw:            rawrec,
			ID:             uid,
			Domain:         a.Domain,
			Punycode:       punny,
			Name:           a.RecordName,
			Extension:      ext,
			WhoisServer:    whois,
			CreatedDate:    cdate.UTC().Format("2006-01-02T15:04:05Z07:00"),
			UpdatedDate:    udate.UTC().Format("2006-01-02T15:04:05Z07:00"),
			ExpirationDate: edate.UTC().Format("2006-01-02T15:04:05Z07:00"),
			Status:         []string{rstatus},
		},
	}, nil
}
