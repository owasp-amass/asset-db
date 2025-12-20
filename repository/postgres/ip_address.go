// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/owasp-amass/asset-db/types"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Params: @record::jsonb
const upsertIPAddressText = `SELECT public.ipaddress_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectIPAddressByID = `
SELECT a.id, a.created_at, a.updated_at, a.ip_address, a.attrs
FROM public.ipaddress_get_by_id(@row_id::bigint) AS a;`

type ipAddressAttributes struct {
	Type string `json:"type,omitempty"`
}

func (r *PostgresRepository) upsertIPAddress(ctx context.Context, a *oamnet.IPAddress) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid IP address provided")
	}
	if !a.Address.IsValid() {
		return 0, errors.New("IP address is invalid")
	}
	if a.Address.IsUnspecified() {
		return 0, errors.New("unspecified IP addresses are not allowed")
	}

	switch a.Type {
	case "":
		return 0, errors.New("IP address type cannot be empty")
	case "IPv4":
		if !a.Address.Is4() {
			return 0, errors.New("mismatched IP address and type")
		}
	case "IPv6":
		if !a.Address.Is6() {
			return 0, errors.New("mismatched IP address and type")
		}
	default:
		return 0, errors.New("IP address type must be either IPv4 or IPv6")
	}

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.ip_address.upsert",
		SQLText: upsertIPAddressText,
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

func (r *PostgresRepository) fetchIPAddressByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.ip_address.by_id",
		SQLText: selectIPAddressByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamnet.IPAddress
	var c, u, addrstr, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &addrstr, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no IP address found")
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

	addr, err := netip.ParseAddr(addrstr)
	if err != nil {
		return nil, err
	}
	a.Address = addr

	if !a.Address.IsValid() {
		return nil, errors.New("IP address is invalid")
	}
	if a.Address.IsUnspecified() {
		return nil, errors.New("the IP address is unspecified")
	}

	var attrs ipAddressAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Type = attrs.Type

	switch a.Type {
	case "":
		return nil, errors.New("IP address type is missing")
	case "IPv4":
		if !a.Address.Is4() {
			return nil, errors.New("mismatched IP address and type")
		}
	case "IPv6":
		if !a.Address.Is6() {
			return nil, errors.New("mismatched IP address and type")
		}
	default:
		return nil, errors.New("IP address type must be either IPv4 or IPv6")
	}

	return e, nil
}
