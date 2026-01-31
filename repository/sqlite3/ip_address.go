// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	_ "modernc.org/sqlite"
)

// Params: :ip_address_text, :attrs
const upsertIPAddressText = `
INSERT INTO ipaddress(ip_address, attrs)
VALUES (:ip_address_text, :attrs)
ON CONFLICT(ip_address) DO UPDATE SET
	attrs      = json_patch(ipaddress.attrs, excluded.attrs),
    updated_at = CURRENT_TIMESTAMP`

// Param: :ip_address_text
const selectEntityIDByIPAddressText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'ipaddress' LIMIT 1)
  AND natural_key = :ip_address_text
LIMIT 1`

// Param: :row_id
const selectIPAddressByID = `
SELECT id, created_at, updated_at, ip_address, attrs
FROM ipaddress 
WHERE id = :row_id
LIMIT 1`

type ipAddressAttributes struct {
	Type string `json:"type,omitempty"`
}

func (r *SqliteRepository) upsertIPAddress(ctx context.Context, a *oamnet.IPAddress) (int64, error) {
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

	attrs := ipAddressAttributes{
		Type: a.Type,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.ip_address.upsert",
		SQLText: upsertIPAddressText,
		Args: []any{
			sql.Named("ip_address_text", a.Address.String()),
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
		Name:    "asset.ip_address.entity_id_by_ip_address",
		SQLText: selectEntityIDByIPAddressText,
		Args:    []any{sql.Named("ip_address_text", a.Address.String())},
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

func (r *SqliteRepository) fetchIPAddressByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.ip_address.by_id",
		SQLText: selectIPAddressByID,
		Args:    []any{sql.Named("row_id", rowID)},
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
		return nil, errors.New("the IP addresses is unspecified")
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
