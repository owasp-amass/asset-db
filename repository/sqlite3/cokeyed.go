// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// CoKeyedGroups implements repository.CoKeyedGrouper: it groups entities of
// atype that share a blocking key entirely in the database, so a duplicate
// sweep never loads the whole type. It returns the groups of 2..maxGroup
// members (a key shared by more than maxGroup entities is too common to
// discriminate and is dropped); since, when non-zero, limits to keys whose
// backing row changed at or after it.
func (r *SqliteRepository) CoKeyedGroups(ctx context.Context, atype oam.AssetType, key types.CoKey,
	param string, maxGroup int, since time.Time) ([]types.CoKeyGroup, error) {
	if r == nil || r.rpool == nil {
		return nil, errors.New("missing SQLite reader")
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
		base = `SELECT DISTINCT CAST(e.to_entity_id AS TEXT) AS k, CAST(e.from_entity_id AS TEXT) AS id
			FROM edge e
			JOIN entity src ON src.entity_id = e.from_entity_id
			JOIN entity_type_lu t ON t.id = src.etype_id AND t.name = ?
			WHERE e.label = 'id'`
	case types.CoKeyContactRecord:
		// Entities named by the same ContactRecord (edge ContactRecord -"organization"-> entity).
		sinceCol = "e.updated_at"
		base = `SELECT DISTINCT CAST(e.from_entity_id AS TEXT) AS k, CAST(e.to_entity_id AS TEXT) AS id
			FROM edge e
			JOIN entity dst ON dst.entity_id = e.to_entity_id
			JOIN entity_type_lu t ON t.id = dst.etype_id AND t.name = ?
			WHERE e.label = 'organization'`
	case types.CoKeyLocation:
		// Entities pointing at the same Location through an address edge.
		sinceCol = "e.updated_at"
		base = `SELECT DISTINCT CAST(e.to_entity_id AS TEXT) AS k, CAST(e.from_entity_id AS TEXT) AS id
			FROM edge e
			JOIN entity src ON src.entity_id = e.from_entity_id
			JOIN entity_type_lu t ON t.id = src.etype_id AND t.name = ?
			WHERE e.label IN ('legal_address', 'hq_address', 'location')`
	case types.CoKeyRegistration:
		// Organizations sharing a normalized (jurisdiction, registration_id):
		// jurisdiction upper+trim, registration_id upper with whitespace removed.
		// SQLite has no regexp_replace, so strip space, tab, newline, and
		// carriage return explicitly (the whitespace registration ids carry).
		sinceCol = "e.updated_at"
		base = `SELECT DISTINCT
			upper(trim(o.jurisdiction)) || '|' ||
			upper(replace(replace(replace(replace(o.registration_id, ' ', ''), char(9), ''), char(10), ''), char(13), '')) AS k,
			CAST(e.entity_id AS TEXT) AS id
			FROM entity e
			JOIN entity_type_lu t ON t.id = e.etype_id AND t.name = ?
			JOIN organization o ON o.id = e.row_id
			WHERE trim(coalesce(o.jurisdiction, '')) <> '' AND trim(coalesce(o.registration_id, '')) <> ''`
	case types.CoKeyTag:
		if param == "" {
			return nil, errors.New("tag property name required for CoKeyTag")
		}
		sinceCol = "g.updated_at"
		args = append(args, param)
		base = `SELECT DISTINCT g.property_value AS k, CAST(g.entity_id AS TEXT) AS id
			FROM entity_tag g
			JOIN entity e ON e.entity_id = g.entity_id
			JOIN entity_type_lu t ON t.id = e.etype_id AND t.name = ?
			WHERE g.property_name = ?`
	default:
		return nil, fmt.Errorf("unknown CoKey %d", key)
	}

	if !since.IsZero() {
		base += " AND " + sinceCol + " >= ?"
		args = append(args, since.UTC())
	}
	args = append(args, maxGroup)
	query := fmt.Sprintf(`SELECT k, id FROM (
		SELECT k, id, count(*) OVER (PARTITION BY k) AS n FROM (%s) b
	) w WHERE w.n >= 2 AND w.n <= ? ORDER BY k, id`, base)

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: query, SQLText: query, Args: args, Result: ch})

	var result *rowsReadResult
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result = <-ch:
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var groups []types.CoKeyGroup
	var cur *types.CoKeyGroup
	rows := result.Rows
	for rows.Next() {
		var k, id string
		if err := rows.Scan(&k, &id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if cur == nil || cur.Key != k {
			groups = append(groups, types.CoKeyGroup{Key: k})
			cur = &groups[len(groups)-1]
		}
		cur.IDs = append(cur.IDs, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}

	_ = rows.Close()
	return groups, nil
}
