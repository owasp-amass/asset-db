// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// CoKeyedGroups implements repository.CoKeyedGroups: it groups entities of
// atype that share a blocking key entirely in the database, so a duplicate
// sweep never loads the whole type. It returns the groups of 2..maxGroup
// members (keys shared by more than maxGroup entities are non-discriminating
// and dropped); since, when non-zero, limits to keys whose backing row changed
// at or after it.
func (r *PostgresRepository) CoKeyedGroups(ctx context.Context, atype oam.AssetType, key types.CoKey,
	param string, maxGroup int, since time.Time) ([]types.CoKeyGroup, error) {
	if r == nil || r.DB == nil {
		return nil, errors.New("missing PostgreSQL reader")
	}
	if maxGroup < 2 {
		return nil, errors.New("maxGroup must be at least 2")
	}

	// Each base query selects DISTINCT (k, id): k is the shared key value and id
	// is a member entity id, cast to text so one scan path serves every key.
	args := []any{normalizeType(string(atype))}
	var base, sinceCol string
	switch key {
	case types.CoKeyIdentifier:
		// Entities with an outgoing edge labeled "id" to the same Identifier.
		sinceCol = "e.updated_at"
		base = `SELECT DISTINCT e.to_entity_id::text AS k, e.from_entity_id::text AS id
			FROM public.edge e
			JOIN public.entity src ON src.entity_id = e.from_entity_id
			JOIN public.entity_type_lu t ON t.id = src.etype_id AND t.name = $1
			WHERE e.label = 'id'`
	case types.CoKeyContactRecord:
		// Entities named by the same ContactRecord (edge ContactRecord -"organization"-> entity).
		sinceCol = "e.updated_at"
		base = `SELECT DISTINCT e.from_entity_id::text AS k, e.to_entity_id::text AS id
			FROM public.edge e
			JOIN public.entity dst ON dst.entity_id = e.to_entity_id
			JOIN public.entity_type_lu t ON t.id = dst.etype_id AND t.name = $1
			WHERE e.label = 'organization'`
	case types.CoKeyStreetAddress:
		// Entities pointing at the same StreetAddress through an address edge.
		sinceCol = "e.updated_at"
		base = `SELECT DISTINCT e.to_entity_id::text AS k, e.from_entity_id::text AS id
			FROM public.edge e
			JOIN public.entity src ON src.entity_id = e.from_entity_id
			JOIN public.entity_type_lu t ON t.id = src.etype_id AND t.name = $1
			WHERE e.label IN ('legal_address', 'hq_address', 'street_address')`
	case types.CoKeyRegistration:
		// Organizations sharing a normalized (jurisdiction, registration_id):
		// jurisdiction upper+trim, registration_id upper with whitespace removed.
		sinceCol = "e.updated_at"
		base = `SELECT DISTINCT
			upper(btrim(o.jurisdiction)) || '|' || upper(regexp_replace(o.registration_id, '\s', '', 'g')) AS k,
			e.entity_id::text AS id
			FROM public.entity e
			JOIN public.entity_type_lu t ON t.id = e.etype_id AND t.name = $1
			JOIN public.organization o ON o.id = e.row_id
			WHERE btrim(coalesce(o.jurisdiction, '')) <> '' AND btrim(coalesce(o.registration_id, '')) <> ''`
	case types.CoKeyTag:
		if param == "" {
			return nil, errors.New("tag property name required for CoKeyTag")
		}
		sinceCol = "g.updated_at"
		args = append(args, param)
		base = `SELECT DISTINCT g.property_value AS k, g.entity_id::text AS id
			FROM public.entity_tag g
			JOIN public.entity e ON e.entity_id = g.entity_id
			JOIN public.entity_type_lu t ON t.id = e.etype_id AND t.name = $1
			WHERE g.property_name = $2`
	default:
		return nil, fmt.Errorf("unknown CoKey %d", key)
	}

	if !since.IsZero() {
		args = append(args, since.UTC())
		base += fmt.Sprintf(" AND %s >= $%d", sinceCol, len(args))
	}
	args = append(args, maxGroup)
	query := fmt.Sprintf(`SELECT k, id FROM (
		SELECT k, id, count(*) OVER (PARTITION BY k) AS n FROM (%s) b
	) w WHERE w.n >= 2 AND w.n <= $%d ORDER BY k, id`, base, len(args))

	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var groups []types.CoKeyGroup
	var cur *types.CoKeyGroup
	for rows.Next() {
		var k, id string
		if err := rows.Scan(&k, &id); err != nil {
			return nil, err
		}
		if cur == nil || cur.Key != k {
			groups = append(groups, types.CoKeyGroup{Key: k})
			cur = &groups[len(groups)-1]
		}
		cur.IDs = append(cur.IDs, id)
	}

	return groups, rows.Err()
}
