// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"net/netip"
	"strconv"
	"strings"
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
    updated_at    	= CURRENT_TIMESTAMP`

// Param: :handle
const selectEntityIDByIPNetRecordText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'ipnetrecord' LIMIT 1)
  AND natural_key = :handle
LIMIT 1`

// Param: :row_id
const selectIPNetRecordByID = `
SELECT id, created_at, updated_at, record_cidr, record_name, ip_version, handle, method, record_status,
	   created_date, updated_date, whois_server, parent_handle, start_address, end_address, country 
FROM ipnetrecord
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertIPNetRecord(ctx context.Context, a *oamreg.IPNetRecord) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.ipnet_record.upsert",
		SQLText: upsertIPNetRecordText,
		Args: []any{
			sql.Named("record_cidr", a.CIDR.String()),
			sql.Named("record_name", a.Name),
			sql.Named("ip_version", a.Type),
			sql.Named("handle", a.Handle),
			sql.Named("method", a.Method),
			sql.Named("record_status", strings.Join(a.Status, ",")),
			sql.Named("created_date", a.CreatedDate),
			sql.Named("updated_date", a.UpdatedDate),
			sql.Named("whois_server", a.WhoisServer),
			sql.Named("parent_handle", a.ParentHandle),
			sql.Named("start_address", a.StartAddress.String()),
			sql.Named("end_address", a.EndAddress.String()),
			sql.Named("country", a.Country),
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
		Name:    "asset.ipnet_record.entity_id_by_ipnet_record",
		SQLText: selectEntityIDByIPNetRecordText,
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

func (r *SqliteRepository) fetchIPNetRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.ipnet_record.by_id",
		SQLText: selectIPNetRecordByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var c, u string
	var row_id int64
	var a oamreg.IPNetRecord
	var cidrstr, status, start, end string
	if err := result.Row.Scan(&row_id, &c, &u, &cidrstr, &a.Name, &a.Type, &a.Handle, &a.Method, &status,
		&a.CreatedDate, &a.UpdatedDate, &a.WhoisServer, &a.ParentHandle, &start, &end, &a.Country); err != nil {
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

	ipnet, err := netip.ParsePrefix(cidrstr)
	if err != nil {
		return nil, err
	}
	a.CIDR = ipnet

	if status != "" {
		a.Status = strings.Split(status, ",")
	}

	startaddr, err := netip.ParseAddr(start)
	if err != nil {
		return nil, err
	}
	a.StartAddress = startaddr

	endaddr, err := netip.ParseAddr(end)
	if err != nil {
		return nil, err
	}
	a.EndAddress = endaddr

	return e, nil
}
