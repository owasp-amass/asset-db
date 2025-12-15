// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Params: :netblock_cidr, :attrs
const upsertNetblockText = `
INSERT INTO netblock (netblock_cidr, attrs)
VALUES (:netblock_cidr, :attrs)
ON CONFLICT(netblock_cidr) DO UPDATE SET
  attrs      = json_patch(netblock.attrs, excluded.attrs),
  updated_at = CURRENT_TIMESTAMP`

// Param: :netblock_cidr
const selectEntityIDByNetblockText = `
SELECT entity_id FROM entity
WHERE etype_id = (SELECT id FROM entity_type_lu WHERE name = 'netblock' LIMIT 1)
  AND natural_key = :netblock_cidr
LIMIT 1`

// Param: :row_id
const selectNetblockByID = `
SELECT id, created_at, updated_at, netblock_cidr, attrs
FROM netblock
WHERE id = :row_id
LIMIT 1`

type netblockAttributes struct {
	Type string `json:"type,omitempty"`
}

func (r *PostgresRepository) upsertNetblock(ctx context.Context, a *oamnet.Netblock) (int64, error) {
	if a == nil {
		return 0, errors.New("invalid netblock provided")
	}
	if !a.CIDR.IsValid() {
		return 0, errors.New("netblock CIDR is invalid")
	}
	if a.CIDR.Addr().IsUnspecified() {
		return 0, errors.New("unspecified IP addresses are not allowed")
	}

	switch a.Type {
	case "":
		return 0, errors.New("CIDR IP version cannot be empty")
	case "IPv4":
		if !a.CIDR.Addr().Is4() {
			return 0, errors.New("mismatched CIDR IP version and type")
		}
	case "IPv6":
		if !a.CIDR.Addr().Is6() {
			return 0, errors.New("mismatched CIDR IP version and type")
		}
	default:
		return 0, errors.New("CIDR IP version must be either IPv4 or IPv6")
	}

	attrs := netblockAttributes{
		Type: a.Type,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "asset.netblock.upsert",
		SQLText: upsertNetblockText,
		Args: []any{
			sql.Named("netblock_cidr", a.CIDR.String()),
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
		Name:    "asset.netblock.entity_id_by_netblock",
		SQLText: selectEntityIDByNetblockText,
		Args:    []any{sql.Named("netblock_cidr", a.CIDR.String())},
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

func (r *PostgresRepository) fetchNetblockByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "asset.netblock.by_id",
		SQLText: selectNetblockByID,
		Args:    []any{sql.Named("row_id", rowID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var row_id int64
	var a oamnet.Netblock
	var c, u, cidrstr, attrsJSON string
	if err := result.Row.Scan(&row_id, &c, &u, &cidrstr, &attrsJSON); err != nil {
		return nil, err
	}

	if row_id == 0 {
		return nil, errors.New("no netblock record found")
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

	cidr, err := netip.ParsePrefix(cidrstr)
	if err != nil {
		return nil, err
	}
	a.CIDR = cidr

	if !a.CIDR.IsValid() {
		return nil, errors.New("CIDR is invalid")
	}
	if a.CIDR.Addr().IsUnspecified() {
		return nil, errors.New("the CIDR is unspecified")
	}

	var attrs netblockAttributes
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return nil, err
	}
	a.Type = attrs.Type

	switch a.Type {
	case "":
		return nil, errors.New("CIDR IP version cannot be empty")
	case "IPv4":
		if !a.CIDR.Addr().Is4() {
			return nil, errors.New("mismatched CIDR IP version and type")
		}
	case "IPv6":
		if !a.CIDR.Addr().Is6() {
			return nil, errors.New("mismatched CIDR IP version and type")
		}
	default:
		return nil, errors.New("CIDR IP version must be either IPv4 or IPv6")
	}

	return e, nil
}
