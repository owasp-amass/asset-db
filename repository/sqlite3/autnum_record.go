// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
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

type AutnumRecord struct {
	ID           int64      `json:"id"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
	RecordName   *string    `json:"record_name,omitempty"`
	Handle       string     `json:"handle"`
	ASN          int64      `json:"asn"`
	RecordStatus *string    `json:"record_status,omitempty"`
	CreatedDate  *time.Time `json:"created_date,omitempty"`
	UpdatedDate  *time.Time `json:"updated_date,omitempty"`
	WhoisServer  *string    `json:"whois_server,omitempty"`
}

func (s *Statements) UpsertAutnumRecord(ctx context.Context, handle string, asn int64, recordName, recordStatus *string, createdDate, updatedDate *time.Time, whoisServer *string, attrsJSON string) (int64, error) {
	row := s.UpsertAutnumRecordStmt.QueryRowContext(ctx,
		sql.Named("handle", handle),
		sql.Named("asn", asn),
		sql.Named("record_name", recordName),
		sql.Named("record_status", recordStatus),
		sql.Named("created_date", createdDate),
		sql.Named("updated_date", updatedDate),
		sql.Named("whois_server", whoisServer),
		sql.Named("attrs", attrsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchAutnumRecordByRowID(ctx context.Context, rowID int64) (*AutnumRecord, error) {
	query := `SELECT id, created_at, updated_at, record_name, handle, asn, record_status, created_date, updated_date, whois_server
		      FROM autnumrecord WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "autnumrecord", query)
	if err != nil {
		return nil, err
	}

	var a AutnumRecord
	var c, u, cd, ud *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.RecordName, &a.Handle, &a.ASN, &a.RecordStatus, &cd, &ud, &a.WhoisServer,
	); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	a.CreatedDate = parseTS(cd)
	a.UpdatedDate = parseTS(ud)
	return &a, nil
}
