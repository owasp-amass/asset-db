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
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Params: :ip_version, :ip_address_text
const upsertIPAddressText = `
INSERT INTO ipaddress(ip_version, ip_address)
VALUES (:ip_version, :ip_address_text)
ON CONFLICT(ip_address) DO UPDATE SET
    ip_version = COALESCE(excluded.ip_version, ipaddress.ip_version),
    updated_at = CURRENT_TIMESTAMP`

// Param: :ip_address_text
const selectEntityIDByIPAddressText = `
SELECT entity_id FROM entity
WHERE type_id = (SELECT id FROM entity_type_lu WHERE name = 'ipaddress' LIMIT 1)
  AND display_value = :ip_address_text
LIMIT 1`

// Param: :row_id
const selectIPAddressByID = `
SELECT id, created_at, updated_at, ip_version, ip_address 
FROM ipaddress 
WHERE id = :row_id
LIMIT 1`

func (r *SqliteRepository) upsertIPAddress(ctx context.Context, a *oamnet.IPAddress) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.ip_address.upsert",
		SQLText: upsertIPAddressText,
		Args: []any{
			sql.Named("ip_version", a.Type),
			sql.Named("ip_address", a.Address),
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

	var id int64
	var c, u *string
	var addrstr, iptype string
	if err := result.Row.Scan(&id, &c, &u, &iptype, &addrstr); err != nil {
		return nil, err
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	addr, err := netip.ParseAddr(addrstr)
	if err != nil {
		return nil, err
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: created.In(time.UTC).Local(),
		LastSeen:  updated.In(time.UTC).Local(),
		Asset: &oamnet.IPAddress{
			Address: addr,
			Type:    iptype,
		},
	}, nil
}
