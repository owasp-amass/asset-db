// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// IPNETRECORD ----------------------------------------------------------------
// Params: :record_cidr, :record_name, :ip_version, :handle, :method, :record_status,
//
//	:created_date, :updated_date, :whois_server, :parent_handle, :start_address, :end_address, :country, :attrs
const tmplUpsertIPNetRecord = `
WITH
  row_try AS (
    INSERT INTO ipnetrecord(
      record_cidr, record_name, ip_version, handle, method, record_status,
      created_date, updated_date, whois_server, parent_handle, start_address, end_address, country
    ) VALUES (
      :record_cidr, :record_name, :ip_version, :handle, :method, :record_status,
      :created_date, :updated_date, :whois_server, :parent_handle, :start_address, :end_address, :country
    )
    ON CONFLICT(record_cidr) DO UPDATE SET
      record_name   = COALESCE(excluded.record_name,   ipnetrecord.record_name),
      ip_version    = COALESCE(excluded.ip_version,    ipnetrecord.ip_version),
      handle        = COALESCE(excluded.handle,        ipnetrecord.handle),
      method        = COALESCE(excluded.method,        ipnetrecord.method),
      record_status = COALESCE(excluded.record_status, ipnetrecord.record_status),
      created_date  = COALESCE(excluded.created_date,  ipnetrecord.created_date),
      updated_date  = COALESCE(excluded.updated_date,  ipnetrecord.updated_date),
      whois_server  = COALESCE(excluded.whois_server,  ipnetrecord.whois_server),
      parent_handle = COALESCE(excluded.parent_handle, ipnetrecord.parent_handle),
      start_address = COALESCE(excluded.start_address, ipnetrecord.start_address),
      end_address   = COALESCE(excluded.end_address,   ipnetrecord.end_address),
      country       = COALESCE(excluded.country,       ipnetrecord.country),
      updated_at    = CASE WHEN
        (excluded.record_name IS NOT ipnetrecord.record_name) OR
        (excluded.ip_version  IS NOT ipnetrecord.ip_version) OR
        (excluded.handle      IS NOT ipnetrecord.handle) OR
        (excluded.method      IS NOT ipnetrecord.method) OR
        (excluded.record_status IS NOT ipnetrecord.record_status) OR
        (excluded.created_date IS NOT ipnetrecord.created_date) OR
        (excluded.updated_date IS NOT ipnetrecord.updated_date) OR
        (excluded.whois_server IS NOT ipnetrecord.whois_server) OR
        (excluded.parent_handle IS NOT ipnetrecord.parent_handle) OR
        (excluded.start_address IS NOT ipnetrecord.start_address) OR
        (excluded.end_address IS NOT ipnetrecord.end_address) OR
        (excluded.country IS NOT ipnetrecord.country)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE ipnetrecord.updated_at END
    WHERE (excluded.record_name IS NOT ipnetrecord.record_name) OR
          (excluded.ip_version  IS NOT ipnetrecord.ip_version) OR
          (excluded.handle      IS NOT ipnetrecord.handle) OR
          (excluded.method      IS NOT ipnetrecord.method) OR
          (excluded.record_status IS NOT ipnetrecord.record_status) OR
          (excluded.created_date IS NOT ipnetrecord.created_date) OR
          (excluded.updated_date IS NOT ipnetrecord.updated_date) OR
          (excluded.whois_server IS NOT ipnetrecord.whois_server) OR
          (excluded.parent_handle IS NOT ipnetrecord.parent_handle) OR
          (excluded.start_address IS NOT ipnetrecord.start_address) OR
          (excluded.end_address IS NOT ipnetrecord.end_address) OR
          (excluded.country IS NOT ipnetrecord.country)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM ipnetrecord WHERE record_cidr=:record_cidr OR handle=:handle LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('ipnetrecord')
    ON CONFLICT(name) DO NOTHING RETURNING id
  ),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='ipnetrecord' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :record_cidr, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:record_cidr LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'ipnetrecord',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

type IPNetRecord struct {
	ID           int64      `json:"id"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
	RecordCIDR   string     `json:"record_cidr"`
	RecordName   string     `json:"record_name"`
	IPVersion    string     `json:"ip_version"`
	Handle       string     `json:"handle"`
	Method       *string    `json:"method,omitempty"`
	RecordStatus *string    `json:"record_status,omitempty"`
	CreatedDate  *time.Time `json:"created_date,omitempty"`
	UpdatedDate  *time.Time `json:"updated_date,omitempty"`
	WhoisServer  *string    `json:"whois_server,omitempty"`
	ParentHandle *string    `json:"parent_handle,omitempty"`
	StartAddress *string    `json:"start_address,omitempty"`
	EndAddress   *string    `json:"end_address,omitempty"`
	Country      *string    `json:"country,omitempty"`
}

func (s *Statements) UpsertIPNetRecord(ctx context.Context, a *oamreg.IPNetRecord) (int64, error) {
	row := s.UpsertIPNetRecordStmt.QueryRowContext(ctx,
		sql.Named("record_cidr", a.CIDR.String()),
		sql.Named("record_name", a.Name),
		sql.Named("ip_version", a.Type),
		sql.Named("handle", a.Handle),
		sql.Named("method", a.Method),
		sql.Named("record_status", a.Status),
		sql.Named("created_date", a.CreatedDate),
		sql.Named("updated_date", a.UpdatedDate),
		sql.Named("whois_server", a.WhoisServer),
		sql.Named("parent_handle", a.ParentHandle),
		sql.Named("start_address", a.StartAddress.String()),
		sql.Named("end_address", a.EndAddress.String()),
		sql.Named("country", a.Country),
		sql.Named("attrs", "{}"),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchIPNetRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, record_cidr, record_name, ip_version, handle, method, record_status,
		      created_date, updated_date, whois_server, parent_handle, start_address, end_address, country
		      FROM ipnetrecord WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "ipnetrecord", query)
	if err != nil {
		return nil, err
	}

	var a IPNetRecord
	var c, u, cd, ud *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.RecordCIDR, &a.RecordName, &a.IPVersion, &a.Handle, &a.Method,
		&a.RecordStatus, &cd, &ud, &a.WhoisServer, &a.ParentHandle, &a.StartAddress, &a.EndAddress, &a.Country,
	); err != nil {
		return nil, err
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	if a.CreatedDate == nil || a.UpdatedDate == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	ipnet, err := netip.ParsePrefix(a.RecordCIDR)
	if err != nil {
		return nil, err
	}

	var method string
	if a.Method != nil {
		method = *a.Method
	}

	var rstatus string
	if a.RecordStatus != nil {
		rstatus = *a.RecordStatus
	}

	var phandle string
	if a.ParentHandle != nil {
		phandle = *a.ParentHandle
	}

	var whois string
	if a.WhoisServer != nil {
		whois = *a.WhoisServer
	}

	var saddrstr string
	if a.StartAddress != nil {
		saddrstr = *a.StartAddress
	}

	startaddr, err := netip.ParseAddr(saddrstr)
	if err != nil {
		return nil, err
	}

	var eaddrstr string
	if a.EndAddress != nil {
		eaddrstr = *a.EndAddress
	}

	endaddr, err := netip.ParseAddr(eaddrstr)
	if err != nil {
		return nil, err
	}

	var country string
	if a.Country != nil {
		country = *a.Country
	}

	var cdate string
	if cd != nil {
		cdate = *cd
	}

	var udate string
	if ud != nil {
		udate = *ud
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: (*a.CreatedAt).In(time.UTC).Local(),
		LastSeen:  (*a.UpdatedAt).In(time.UTC).Local(),
		Asset: &oamreg.IPNetRecord{
			CIDR:         ipnet,
			Handle:       a.Handle,
			StartAddress: startaddr,
			EndAddress:   endaddr,
			Type:         a.IPVersion,
			Name:         a.RecordName,
			Method:       method,
			Country:      country,
			ParentHandle: phandle,
			WhoisServer:  whois,
			CreatedDate:  cdate,
			UpdatedDate:  udate,
			Status:       []string{rstatus},
		},
	}, nil
}
