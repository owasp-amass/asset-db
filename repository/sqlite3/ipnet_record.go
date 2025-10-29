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

// Params: :record_cidr, :record_name, :ip_version, :handle, :method, :record_status, :created_date,
//
//	:updated_date, :whois_server, :parent_handle, :start_address, :end_address, :country
const upsertIPNetRecordText = `
INSERT INTO ipnetrecord(
	record_cidr, record_name, ip_version, handle, method, record_status, created_date, 
	updated_date, whois_server, parent_handle, start_address, end_address, country) 
VALUES (
	:record_cidr, :record_name, :ip_version, :handle, :method, :record_status, :created_date, 
	:updated_date, :whois_server, :parent_handle, :start_address, :end_address, :country)
ON CONFLICT(handle) DO UPDATE SET
	record_cidr 	= COALESCE(excluded.record_cidr,   ipnetrecord.record_cidr),
    record_name   	= COALESCE(excluded.record_name,   ipnetrecord.record_name),
    ip_version    	= COALESCE(excluded.ip_version,    ipnetrecord.ip_version),
    method        	= COALESCE(excluded.method,        ipnetrecord.method),
    record_status 	= COALESCE(excluded.record_status, ipnetrecord.record_status),
    created_date  	= COALESCE(excluded.created_date,  ipnetrecord.created_date),
    updated_date  	= COALESCE(excluded.updated_date,  ipnetrecord.updated_date),
    whois_server  	= COALESCE(excluded.whois_server,  ipnetrecord.whois_server),
    parent_handle 	= COALESCE(excluded.parent_handle, ipnetrecord.parent_handle),
    start_address 	= COALESCE(excluded.start_address, ipnetrecord.start_address),
    end_address   	= COALESCE(excluded.end_address,   ipnetrecord.end_address),
    country       	= COALESCE(excluded.country,       ipnetrecord.country),
    updated_at    	= CURRENT_TIMESTAMP;`

// Param: :handle
const selectEntityIDByIPNetRecordText = `
SELECT entity_id FROM entities
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'ipnetrecord')
  AND display_value = :handle
LIMIT 1;`

// Param: :row_id
const selectIPNetRecordByID = `
SELECT id, created_at, updated_at, record_cidr, record_name, ip_version, handle, method, record_status,
	   created_date, updated_date, whois_server, parent_handle, start_address, end_address, country 
FROM ipnetrecord
WHERE id = :row_id
LIMIT 1;`

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

func (r *SqliteRepository) upsertIPNetRecord(ctx context.Context, a *oamreg.IPNetRecord) (int64, error) {
	const keySel = "asset.ipnet_record.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertIPNetRecordText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
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
	)

	const keySel2 = "asset.ipnet_record.entity_id_by_ipnet_record"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityIDByIPNetRecordText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx, sql.Named("handle", a.Handle)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) fetchIPNetRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	const keySel = "asset.fqdn.by_id"
	st, err := r.queries.getOrPrepare(ctx, keySel, selectIPNetRecordByID)
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
		CreatedAt: a.CreatedAt.In(time.UTC).Local(),
		LastSeen:  a.UpdatedAt.In(time.UTC).Local(),
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
