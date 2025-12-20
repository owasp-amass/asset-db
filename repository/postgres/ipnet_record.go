// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/owasp-amass/asset-db/types"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Params: @record::jsonb
const upsertIPNetRecordText = `SELECT public.ipnetrecord_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectIPNetRecordByID = `
SELECT a.id, a.created_at, a.updated_at, a.record_cidr, a.record_name, a.handle,
	   a.whois_server, a.parent_handle, a.start_address, a.end_address, a.attrs
FROM public.ipnetrecord_get_by_id(@row_id::bigint) AS a;`

type ipnetRecordAttributes struct {
	Raw         string   `json:"raw,omitempty"`
	Type        string   `json:"type,omitempty"`
	Method      string   `json:"method,omitempty"`
	Status      []string `json:"status,omitempty"`
	CreatedDate string   `json:"created_date,omitempty"`
	UpdatedDate string   `json:"updated_date,omitempty"`
	Country     string   `json:"country,omitempty"`
}

func (r *PostgresRepository) upsertIPNetRecord(ctx context.Context, a *oamreg.IPNetRecord) (int64, error) {
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

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.ipnet_record.upsert",
		SQLText: upsertIPNetRecordText,
		Args:    pgx.NamedArgs{"record": string(record)},
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

func (r *PostgresRepository) fetchIPNetRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.ipnet_record.by_id",
		SQLText: selectIPNetRecordByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
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
