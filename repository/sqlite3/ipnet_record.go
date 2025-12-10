// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Params: :record_cidr, :record_name, :handle, :whois_server, :parent_handle,
// :start_address, :end_address, :attrs
const upsertIPNetRecordText = `
INSERT INTO ipnetrecord(record_cidr, record_name, handle, whois_server, 
parent_handle, start_address, end_address, attrs) 
VALUES (:record_cidr, :record_name, :handle, :whois_server, :parent_handle, 
:start_address, :end_address, :attrs)
ON CONFLICT(handle) DO UPDATE SET
	record_cidr 	= COALESCE(excluded.record_cidr,   ipnetrecord.record_cidr),
    record_name   	= COALESCE(excluded.record_name,   ipnetrecord.record_name),
    whois_server  	= COALESCE(excluded.whois_server,  ipnetrecord.whois_server),
    parent_handle 	= COALESCE(excluded.parent_handle, ipnetrecord.parent_handle),
    start_address 	= COALESCE(excluded.start_address, ipnetrecord.start_address),
    end_address   	= COALESCE(excluded.end_address,   ipnetrecord.end_address),
	attrs           = json_patch(ipnetrecord.attrs,    excluded.attrs),
    updated_at    	= CURRENT_TIMESTAMP`

// Param: :handle
const selectEntityIDByIPNetRecordText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'ipnetrecord' LIMIT 1)
  AND natural_key = :handle
LIMIT 1`

// Param: :row_id
const selectIPNetRecordByID = `
SELECT id, created_at, updated_at, record_cidr, record_name, handle,
	   whois_server, parent_handle, start_address, end_address, attrs
FROM ipnetrecord
WHERE id = :row_id
LIMIT 1`

type ipnetRecordAttributes struct {
	Raw         string   `json:"raw,omitempty"`
	Type        string   `json:"type,omitempty"`
	Method      string   `json:"method,omitempty"`
	Status      []string `json:"status,omitempty"`
	CreatedDate string   `json:"created_date,omitempty"`
	UpdatedDate string   `json:"updated_date,omitempty"`
	Country     string   `json:"country,omitempty"`
}

func (r *SqliteRepository) upsertIPNetRecord(ctx context.Context, a *oamreg.IPNetRecord) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid ipnet record provided")
	}
	if !a.CIDR.IsValid() {
		return 0, errors.New("ipnet record CIDR is invalid")
	}
	if a.Name == "" {
		return 0, errors.New("ipnet record name cannot be empty")
	}
	if a.Handle == "" {
		return 0, errors.New("ipnet record handle cannot be empty")
	}
	if !a.StartAddress.IsValid() || a.StartAddress.IsUnspecified() || !a.CIDR.Contains(a.StartAddress) {
		return 0, errors.New("ipnet record start address is invalid")
	}
	if !a.EndAddress.IsValid() || a.EndAddress.IsUnspecified() || !a.CIDR.Contains(a.EndAddress) {
		return 0, errors.New("ipnet record end address is invalid")
	}
	if _, err := parseTimestamp(a.CreatedDate); err != nil {
		return 0, fmt.Errorf("ipnet record must have a valid created date: %v", err)
	}
	if _, err := parseTimestamp(a.UpdatedDate); err != nil {
		return 0, fmt.Errorf("ipnet record must have a valid updated date: %v", err)
	}

	switch a.Type {
	case "":
		return 0, errors.New("IP version cannot be empty")
	case "IPv4":
		if !a.CIDR.Addr().Is4() {
			return 0, errors.New("mismatched CIDR IP version and type")
		}
	case "IPv6":
		if !a.CIDR.Addr().Is6() {
			return 0, errors.New("mismatched CIDR IP version and type")
		}
	default:
		return 0, errors.New("CIDR type must be either IPv4 or IPv6")
	}

	attrs := ipnetRecordAttributes{
		Raw:         a.Raw,
		Type:        a.Type,
		Method:      a.Method,
		Status:      a.Status,
		CreatedDate: a.CreatedDate,
		UpdatedDate: a.UpdatedDate,
		Country:     a.Country,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.ipnet_record.upsert",
		SQLText: upsertIPNetRecordText,
		Args: []any{
			sql.Named("record_cidr", a.CIDR.String()),
			sql.Named("record_name", a.Name),
			sql.Named("handle", a.Handle),
			sql.Named("whois_server", a.WhoisServer),
			sql.Named("parent_handle", a.ParentHandle),
			sql.Named("start_address", a.StartAddress.String()),
			sql.Named("end_address", a.EndAddress.String()),
			sql.Named("attrs", attrsJSON),
		},
		Result: done,
	})
	err = <-done
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

	var row_id int64
	var a oamreg.IPNetRecord
	var c, u, cidrstr, start, end, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &cidrstr, &a.Name, &a.Handle,
		&a.WhoisServer, &a.ParentHandle, &start, &end, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no ipnet record found")
	}
	if a.Name == "" {
		return nil, errors.New("ipnet record name cannot be empty")
	}
	if a.Handle == "" {
		return nil, errors.New("ipnet record handle cannot be empty")
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

	var err error
	a.CIDR, err = netip.ParsePrefix(cidrstr)
	if err != nil {
		return nil, err
	}

	if !a.CIDR.IsValid() {
		return nil, errors.New("ipnet record CIDR is invalid")
	}

	var attrs ipnetRecordAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Raw = attrs.Raw
	a.Type = attrs.Type
	a.Method = attrs.Method
	a.Status = attrs.Status
	a.CreatedDate = attrs.CreatedDate
	a.UpdatedDate = attrs.UpdatedDate
	a.Country = attrs.Country

	switch a.Type {
	case "":
		return nil, errors.New("IP version cannot be empty")
	case "IPv4":
		if !a.CIDR.Addr().Is4() {
			return nil, errors.New("mismatched CIDR IP version and type")
		}
	case "IPv6":
		if !a.CIDR.Addr().Is6() {
			return nil, errors.New("mismatched CIDR IP version and type")
		}
	default:
		return nil, errors.New("CIDR type must be either IPv4 or IPv6")
	}

	if _, err := parseTimestamp(a.CreatedDate); err != nil {
		return nil, fmt.Errorf("ipnet record must have a valid created date: %v", err)
	}
	if _, err := parseTimestamp(a.UpdatedDate); err != nil {
		return nil, fmt.Errorf("ipnet record must have a valid updated date: %v", err)
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

	if !a.StartAddress.IsValid() || a.StartAddress.IsUnspecified() || !a.CIDR.Contains(a.StartAddress) {
		return nil, errors.New("ipnet record start address is invalid")
	}
	if !a.EndAddress.IsValid() || a.EndAddress.IsUnspecified() || !a.CIDR.Contains(a.EndAddress) {
		return nil, errors.New("ipnet record end address is invalid")
	}

	return e, nil
}
