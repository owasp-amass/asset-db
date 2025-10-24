// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
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

type Service struct {
	ID           int64            `json:"id"`
	CreatedAt    *time.Time       `json:"created_at,omitempty"`
	UpdatedAt    *time.Time       `json:"updated_at,omitempty"`
	UniqueID     string           `json:"unique_id"`
	ServiceType  string           `json:"service_type"`
	OutputData   *string          `json:"output_data,omitempty"`
	OutputLength *int64           `json:"output_length,omitempty"`
	Attributes   *json.RawMessage `json:"attributes,omitempty"` // JSON
}

func (s *Statements) UpsertService(ctx context.Context, serv *Service, attrsJSON string) (int64, error) {
	row := s.UpsertServiceStmt.QueryRowContext(ctx,
		sql.Named("unique_id", serv.UniqueID),
		sql.Named("service_type", serv.ServiceType),
		sql.Named("output_data", serv.OutputData),
		sql.Named("output_length", serv.OutputLength),
		sql.Named("attributes", serv.Attributes),
		sql.Named("attrs", attrsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (r *Queries) fetchServiceByRowID(ctx context.Context, rowID int64) (*Service, error) {
	query := `SELECT id, created_at, updated_at, unique_id, service_type, output_data, output_length, attributes
		      FROM service WHERE id = ?`

	st, err := r.getOrPrepare(ctx, "service", query)
	if err != nil {
		return nil, err
	}

	var a Service
	var c, u *string
	var outLen *int64
	var attrsStr *string
	if err := st.QueryRowContext(ctx, rowID).Scan(
		&a.ID, &c, &u, &a.UniqueID, &a.ServiceType, &a.OutputData, &outLen, &attrsStr,
	); err != nil {
		return nil, err
	}
	if attrsStr != nil && strings.TrimSpace(*attrsStr) != "" {
		raw := json.RawMessage(*attrsStr)
		a.Attributes = &raw
	}

	a.CreatedAt = parseTS(c)
	a.UpdatedAt = parseTS(u)
	a.OutputLength = outLen
	return &a, nil
}
