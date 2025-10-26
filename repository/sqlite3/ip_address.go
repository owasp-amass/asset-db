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

// IPADDRESS ------------------------------------------------------------------
// Params: :ip_version, :ip_address_text, :attrs
const tmplUpsertIPAddress = `
WITH
  row_try AS (
    INSERT INTO ipaddress(ip_version, ip_address)
    VALUES (:ip_version, :ip_address_text)
    ON CONFLICT(ip_address) DO UPDATE SET
      ip_version = COALESCE(excluded.ip_version, ipaddress.ip_version),
      updated_at = CASE WHEN (excluded.ip_version IS NOT ipaddress.ip_version)
                   THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE ipaddress.updated_at END
    WHERE (excluded.ip_version IS NOT ipaddress.ip_version)
    RETURNING id
  ),
  row_id_cte AS (
    SELECT id AS row_id FROM row_try
    UNION ALL SELECT id AS row_id FROM ipaddress WHERE ip_address = :ip_address_text LIMIT 1
  ),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('ipaddress')
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  type_id AS (
    SELECT id FROM ensure_type
    UNION ALL SELECT id FROM entity_type_lu WHERE name = 'ipaddress' LIMIT 1
  ),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :ip_address_text, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}'))
        ELSE entities.attrs
      END,
      updated_at = CASE
        WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (
    SELECT entity_id FROM ent_ins
    UNION ALL SELECT entity_id FROM entities
    WHERE type_id = (SELECT id FROM type_id) AND display_value = :ip_address_text
    LIMIT 1
  ),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id), 'ipaddress', (SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name, row_id) DO UPDATE SET
      entity_id  = excluded.entity_id,
      updated_at = strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

func (s *Statements) UpsertIPAddress(ctx context.Context, a *oamnet.IPAddress) (int64, error) {
	row := s.UpsertIPAddressStmt.QueryRowContext(ctx,
		sql.Named("ip_version", a.Type),
		sql.Named("ip_address", a.Address),
		sql.Named("attrs", "{}"),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchIPAddressByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, ip_version, ip_address FROM ipaddress WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "ipaddress", query)
	if err != nil {
		return nil, err
	}

	var id int64
	var c, u *string
	var addrstr, iptype string
	if err := st.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &iptype, &addrstr); err != nil {
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
		CreatedAt: (*created).In(time.UTC).Local(),
		LastSeen:  (*updated).In(time.UTC).Local(),
		Asset: &oamnet.IPAddress{
			Address: addr,
			Type:    iptype,
		},
	}, nil
}
