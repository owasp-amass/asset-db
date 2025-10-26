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

// NETBLOCK -------------------------------------------------------------------
// Params: :netblock_cidr, :ip_version, :attrs
const tmplUpsertNetblock = `
WITH
  row_try AS (
    INSERT INTO netblock(netblock_cidr, ip_version) VALUES (:netblock_cidr, :ip_version)
    ON CONFLICT(netblock_cidr) DO UPDATE SET
      ip_version = COALESCE(excluded.ip_version, netblock.ip_version),
      updated_at = CASE WHEN (excluded.ip_version IS NOT netblock.ip_version)
                   THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE netblock.updated_at END
    WHERE (excluded.ip_version IS NOT netblock.ip_version)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM netblock WHERE netblock_cidr=:netblock_cidr LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('netblock') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='netblock' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :netblock_cidr, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:netblock_cidr LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'netblock',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

func (s *Statements) UpsertNetblock(ctx context.Context, a *oamnet.Netblock) (int64, error) {
	row := s.UpsertNetblockStmt.QueryRowContext(ctx,
		sql.Named("netblock_cidr", a.CIDR.String()),
		sql.Named("ip_version", a.Type),
		sql.Named("attrs", "{}"),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchNetblockByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, netblock_cidr, ip_version FROM netblock WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "netblock", query)
	if err != nil {
		return nil, err
	}

	var id int64
	var c, u, ipver *string
	var netstr string
	if err := st.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &netstr, &ipver); err != nil {
		return nil, err
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	cidr, err := netip.ParsePrefix(netstr)
	if err != nil {
		return nil, err
	}

	var version string
	if ipver != nil {
		version = *ipver
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: (*created).In(time.UTC).Local(),
		LastSeen:  (*updated).In(time.UTC).Local(),
		Asset: &oamnet.Netblock{
			CIDR: cidr,
			Type: version,
		},
	}, nil
}
