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
const upsertNetblockText = `SELECT public.netblock_upsert_entity_json(@record::jsonb);`

// Param: @row_id::bigint
const selectNetblockByID = `
SELECT a.id, a.created_at, a.updated_at, a.netblock_cidr, a.attrs
FROM public.netblock_get_by_id(@row_id::bigint) AS a;`

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

	record, err := a.JSON()
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.netblock.upsert",
		SQLText: upsertNetblockText,
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

func (r *PostgresRepository) fetchNetblockByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "asset.netblock.by_id",
		SQLText: selectNetblockByID,
		Args:    pgx.NamedArgs{"row_id": rowID},
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
