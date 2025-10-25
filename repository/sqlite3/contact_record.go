// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
)

// CONTACTRECORD --------------------------------------------------------------
// Params: :discovered_at, :attrs
const tmplUpsertContactRecord = `
WITH
  row_try AS (
    INSERT INTO contactrecord(discovered_at) VALUES (:discovered_at)
    ON CONFLICT(discovered_at) DO NOTHING
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM contactrecord WHERE discovered_at=:discovered_at LIMIT 1),
  ensure_type AS (
    INSERT INTO entity_type_lu(name) VALUES ('contactrecord')
    ON CONFLICT(name) DO NOTHING RETURNING id
  ),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='contactrecord' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :discovered_at, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins
             UNION ALL SELECT entity_id FROM entities
             WHERE type_id=(SELECT id FROM type_id) AND display_value=:discovered_at LIMIT 1),
  ref_up AS (
    INSERT INTO entity_ref(entity_id, table_name, row_id)
    VALUES ((SELECT entity_id FROM ent_id),'contactrecord',(SELECT row_id FROM row_id_cte))
    ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
    WHERE entity_ref.entity_id IS NOT excluded.entity_id
  )
SELECT entity_id FROM ent_id;`

func (s *Statements) UpsertContactRecord(ctx context.Context, a *contact.ContactRecord) (int64, error) {
	row := s.UpsertContactRecordStmt.QueryRowContext(ctx,
		sql.Named("discovered_at", a.DiscoveredAt),
		sql.Named("attrs", ""),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchContactRecordByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, discovered_at FROM contactrecord WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "contactrecord", query)
	if err != nil {
		return nil, err
	}

	var id int64
	var c, u *string
	var disat string
	if err := st.QueryRowContext(ctx, rowID).Scan(&id, &c, &u, &disat); err != nil {
		return nil, err
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: (*created).In(time.UTC).Local(),
		LastSeen:  (*updated).In(time.UTC).Local(),
		Asset:     &contact.ContactRecord{DiscoveredAt: disat},
	}, nil
}
