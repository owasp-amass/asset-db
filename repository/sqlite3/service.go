// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// SERVICE --------------------------------------------------------------------
// Params: :unique_id, :service_type, :output_data, :output_length, :attributes, :attrs
const tmplUpsertService = `
WITH
  row_try AS (
    INSERT INTO service(unique_id, service_type, output_data, output_length, attributes)
    VALUES (:unique_id, :service_type, :output_data, :output_length, :attributes)
    ON CONFLICT(unique_id) DO UPDATE SET
      service_type = COALESCE(excluded.service_type, service.service_type),
      output_data  = COALESCE(excluded.output_data,  service.output_data),
      output_length= COALESCE(excluded.output_length,service.output_length),
      attributes   = COALESCE(excluded.attributes,   service.attributes),
      updated_at   = CASE WHEN
        (excluded.service_type IS NOT service.service_type) OR
        (excluded.output_data  IS NOT service.output_data)  OR
        (excluded.output_length IS NOT service.output_length) OR
        (excluded.attributes   IS NOT service.attributes)
      THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE service.updated_at END
    WHERE (excluded.service_type IS NOT service.service_type) OR
          (excluded.output_data  IS NOT service.output_data)  OR
          (excluded.output_length IS NOT service.output_length) OR
          (excluded.attributes   IS NOT service.attributes)
    RETURNING id
  ),
  row_id_cte AS (SELECT id AS row_id FROM row_try
                 UNION ALL SELECT id AS row_id FROM service WHERE unique_id=:unique_id LIMIT 1),
  ensure_type AS (INSERT INTO entity_type_lu(name) VALUES ('service') ON CONFLICT(name) DO NOTHING RETURNING id),
  type_id AS (SELECT id FROM ensure_type UNION ALL SELECT id FROM entity_type_lu WHERE name='service' LIMIT 1),
  ent_ins AS (
    INSERT INTO entities(type_id, display_value, attrs)
    SELECT (SELECT id FROM type_id), :unique_id, coalesce(:attrs,'{}')
    ON CONFLICT(type_id, display_value) DO UPDATE SET
      attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
      updated_at = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entities.updated_at END
    WHERE json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    RETURNING entity_id
  ),
  ent_id AS (SELECT entity_id FROM ent_ins UNION ALL
             SELECT entity_id FROM entities WHERE type_id=(SELECT id FROM type_id) AND display_value=:unique_id LIMIT 1),
  ref_up AS (INSERT INTO entity_ref(entity_id, table_name, row_id)
             VALUES ((SELECT entity_id FROM ent_id),'service',(SELECT row_id FROM row_id_cte))
             ON CONFLICT(table_name,row_id) DO UPDATE SET entity_id=excluded.entity_id,updated_at=strftime('%Y-%m-%d %H:%M:%f','now')
             WHERE entity_ref.entity_id IS NOT excluded.entity_id)
SELECT entity_id FROM ent_id;`

func (s *Statements) UpsertService(ctx context.Context, a *oamplat.Service) (int64, error) {
	row := s.UpsertServiceStmt.QueryRowContext(ctx,
		sql.Named("unique_id", a.ID),
		sql.Named("service_type", a.Type),
		sql.Named("output_data", a.Output),
		sql.Named("output_length", a.OutputLen),
		sql.Named("attributes", a.Attributes),
		sql.Named("attrs", "{}"),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchServiceByRowID(ctx context.Context, eid, rowID int64) (*types.Entity, error) {
	query := `SELECT id, created_at, updated_at, unique_id, service_type, output_data, output_length, attributes
		      FROM service WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "service", query)
	if err != nil {
		return nil, err
	}

	var id int64
	var c, u *string
	var outLen *int64
	var uid, stype string
	var outdata, attrsStr *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&id, &c, &u, &uid, &stype, &outdata, &outLen, &attrsStr,
	); err != nil {
		return nil, err
	}

	var attributes json.RawMessage
	if attrsStr != nil && strings.TrimSpace(*attrsStr) != "" {
		raw := json.RawMessage(*attrsStr)
		attributes = raw
	}

	created := parseTS(c)
	updated := parseTS(u)
	if created == nil || updated == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	var olen int
	if outLen != nil {
		olen = int(*outLen)
	}

	var odata string
	if outdata != nil {
		odata = *outdata
	}

	var sattrs map[string][]string
	if attributes != nil {
		if err := json.Unmarshal(attributes, &sattrs); err != nil {
			return nil, err
		}
	}

	return &types.Entity{
		ID:        strconv.FormatInt(eid, 10),
		CreatedAt: (*created).In(time.UTC).Local(),
		LastSeen:  (*updated).In(time.UTC).Local(),
		Asset: &oamplat.Service{
			ID:         uid,
			Type:       stype,
			Output:     odata,
			OutputLen:  olen,
			Attributes: sattrs,
		},
	}, nil
}
