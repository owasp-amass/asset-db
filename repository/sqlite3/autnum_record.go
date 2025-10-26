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

// AUTNUMRECORD ---------------------------------------------------------------
// Params: :handle, :asn, :record_name, :record_status, :created_date, :updated_date, :whois_server, :attrs
const tmplUpsertAutnumRecord = `
WITH
  row_try AS (
    INSERT INTO autnumrecord(handle, asn, record_name, record_status, created_date, updated_date, whois_server)
    VALUES (:handle, :asn, :record_name, :record_status, :created_date, :updated_date, :whois_server)
    ON CONFLICT(handle) DO UPDATE SET
      asn           = COALESCE(excluded.asn,           autnumrecord.asn),
      record_name   = COALESCE(excluded.record_name,   autnumrecord.record_name),
      record_status = COALESCE(excluded.record_status, autnumrecord.record_status),
      created_date  = COALESCE(excluded.created_date,  autnumrecord.created_date),
      updated_date  = COALESCE(excluded.updated_date,  autnumrecord.updated_date),
      whois_server  = COALESCE(excluded.whois_server,  autnumrecord.whois_server),
      updated_at    = CASE WHEN
        (excluded.asn           IS NOT autnumrecord.asn) OR
        (excluded.record_name   IS NOT autnumrecord.record_name) OR
        (excluded.record_status IS NOT autnumrecord.record_status) OR
        (excluded.created_date  IS NOT autnumrecord.created_date) OR
        (excluded.updated_date  IS NOT autnumrecord.updated_date) OR
        (excluded.whois_server  IS NOT autnumrecord.whois_server)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE autnumrecord.updated_at END
    WHERE (excluded.asn           IS NOT autnumrecord.asn) OR
          (excluded.record_name   IS NOT autnumrecord.record_name) OR
          (excluded.record_status IS NOT autnumrecord.record_status) OR
          (excluded.created_date  IS NOT autnumrecord.created_date) OR
          (excluded.updated_date  IS NOT autnumrecord.updated_date) OR
          (excluded.whois_server  IS NOT autnumrecord.whois_server)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM autnumrecord WHERE handle=:handle LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('autnumrecord')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='autnumrecord' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :handle, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
              THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
                   THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins
             UNION ALL SELECT entity_id FROM entities
             WHERE type_id=(SELECT id FROM type_id) AND display_value=:handle LIMIT 1),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id),'autnumrecord',(SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

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

func (s *Statements) UpsertAutnumRecord(ctx context.Context, a *oamreg.AutnumRecord) (int64, error) {
	row := s.UpsertAutnumRecordStmt.QueryRowContext(ctx,
		sql.Named("handle", a.Handle),
		sql.Named("asn", a.Number),
		sql.Named("record_name", a.Name),
		sql.Named("record_status", a.Status),
		sql.Named("created_date", a.CreatedDate),
		sql.Named("updated_date", a.UpdatedDate),
		sql.Named("whois_server", a.WhoisServer),
		sql.Named("attrs", ""),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchAutnumRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, record_name, handle, asn, record_status, created_date, updated_date, whois_server
		      FROM autnumrecord WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "autnumrecord", query)
	if err != nil {
		return nil, err
	}

	var a autnum
	var c, u *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.RecordName, &a.Handle, &a.ASN,
		&a.RecordStatus, &a.CreatedDate, &a.UpdatedDate, &a.WhoisServer,
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
		CreatedAt: (*a.CreatedAt).In(time.UTC).Local(),
		LastSeen:  (*a.UpdatedAt).In(time.UTC).Local(),
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
