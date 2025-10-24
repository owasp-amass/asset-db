// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ENSURE EDGE (returns edge_id) ----------------------------------------------
// Params: :etype_name, :from_entity_id, :to_entity_id, :content(JSON)
const tmplEnsureEdge = `
WITH
  ensure_etype AS (
    INSERT INTO edge_type_lu(name) VALUES (:etype_name)
    ON CONFLICT(name) DO NOTHING
    RETURNING id
  ),
  etype_id AS (
    SELECT id FROM ensure_etype
    UNION ALL SELECT id FROM edge_type_lu WHERE name=:etype_name LIMIT 1
  ),
  edge_try AS (
    INSERT INTO edges(etype_id, from_entity_id, to_entity_id, content)
    SELECT (SELECT id FROM etype_id), :from_entity_id, :to_entity_id, coalesce(:content,'{}')
    ON CONFLICT(etype_id, from_entity_id, to_entity_id) DO UPDATE SET
      content = CASE
        WHEN json_patch(edges.content, coalesce(excluded.content,'{}')) IS NOT edges.content
        THEN json_patch(edges.content, coalesce(excluded.content,'{}'))
        ELSE edges.content
      END,
      updated_at = CASE
        WHEN json_patch(edges.content, coalesce(excluded.content,'{}')) IS NOT edges.content
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE edges.updated_at END
    WHERE json_patch(edges.content, coalesce(excluded.content,'{}')) IS NOT edges.content
    RETURNING edge_id
  )
SELECT edge_id FROM edge_try
UNION ALL
SELECT edge_id FROM edges
WHERE etype_id = (SELECT id FROM etype_id)
  AND from_entity_id = :from_entity_id
  AND to_entity_id = :to_entity_id
LIMIT 1;`

type Edge struct {
	EdgeID       int64           `json:"edge_id"`
	EType        string          `json:"etype"` // edge_type_lu.name
	FromEntityID int64           `json:"from_entity_id"`
	ToEntityID   int64           `json:"to_entity_id"`
	Content      json.RawMessage `json:"content,omitempty"` // edges.content
	CreatedAt    *time.Time      `json:"created_at,omitempty"`
	UpdatedAt    *time.Time      `json:"updated_at,omitempty"`
}

type EdgeWithTypes struct {
	Edge
	FromType string `json:"from_type"`
	ToType   string `json:"to_type"`
}

func (s *Statements) EnsureEdge(ctx context.Context, etype string, fromID, toID int64, contentJSON string) (int64, error) {
	row := s.EnsureEdgeStmt.QueryRowContext(ctx,
		sql.Named("etype_name", etype),
		sql.Named("from_entity_id", fromID),
		sql.Named("to_entity_id", toID),
		sql.Named("content", contentJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

// FindEdgeByID loads a single edge (with type name) by edge_id.
func (r *Queries) FindEdgeByID(ctx context.Context, edgeID int64) (*Edge, error) {
	const q = `
SELECT e.edge_id, t.name, e.from_entity_id, e.to_entity_id, e.content, e.created_at, e.updated_at
FROM edges e
JOIN edge_type_lu t ON t.id=e.etype_id
WHERE e.edge_id = ?`
	st, err := r.prepNamed(ctx, "q.edge.byID", q)
	if err != nil {
		return nil, err
	}

	var eg Edge
	var cAt, uAt *string
	var content *string
	if err := st.QueryRowContext(ctx, edgeID).Scan(&eg.EdgeID, &eg.EType, &eg.FromEntityID, &eg.ToEntityID, &content, &cAt, &uAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("edge %d not found", edgeID)
		}
		return nil, err
	}
	if content != nil && strings.TrimSpace(*content) != "" {
		eg.Content = json.RawMessage(*content)
	}
	eg.CreatedAt = parseTS(cAt)
	eg.UpdatedAt = parseTS(uAt)
	return &eg, nil
}

// FindEdgesForEntity returns edges incident to entityID.
// dir = "out", "in", or "" (both). etype optional ("" = any).
// since limits by updated_at >= since (zero time => no limit).
// limit <= 0 => no explicit LIMIT.
func (r *Queries) FindEdgesForEntity(ctx context.Context, entityID int64, dir, etype string, since time.Time, limit int) ([]EdgeWithTypes, error) {
	where := []string{}
	args := []any{}

	base := `
SELECT e.edge_id, te.name,
       e.from_entity_id, e.to_entity_id, e.content, e.created_at, e.updated_at,
       tf.name AS from_type, tt.name AS to_type
FROM edges e
JOIN edge_type_lu te ON te.id = e.etype_id
JOIN entities a ON a.entity_id = e.from_entity_id
JOIN entities b ON b.entity_id = e.to_entity_id
JOIN entity_type_lu tf ON tf.id = a.type_id
JOIN entity_type_lu tt ON tt.id = b.type_id
`
	switch strings.ToLower(strings.TrimSpace(dir)) {
	case "out":
		where = append(where, "e.from_entity_id = ?")
		args = append(args, entityID)
	case "in":
		where = append(where, "e.to_entity_id = ?")
		args = append(args, entityID)
	default:
		where = append(where, "(e.from_entity_id = ? OR e.to_entity_id = ?)")
		args = append(args, entityID, entityID)
	}
	if etype = strings.TrimSpace(etype); etype != "" {
		where = append(where, "te.name = ?")
		args = append(args, etype)
	}
	if !since.IsZero() {
		where = append(where, "e.updated_at >= ?")
		// Use the same format parseTS() expects
		args = append(args, since.UTC().Format("2006-01-02 15:04:05.000"))
	}

	q := base + " WHERE " + strings.Join(where, " AND ") + " ORDER BY e.updated_at DESC"
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	st, err := r.prepNamed(ctx, "q.edges.forEntity:"+dir, q)
	if err != nil {
		return nil, err
	}

	rows, err := st.QueryContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []EdgeWithTypes
	for rows.Next() {
		var eg EdgeWithTypes
		var cAt, uAt *string
		var content *string
		if err := rows.Scan(
			&eg.EdgeID, &eg.EType, &eg.FromEntityID, &eg.ToEntityID, &content, &cAt, &uAt, &eg.FromType, &eg.ToType,
		); err != nil {
			return nil, err
		}
		if content != nil && strings.TrimSpace(*content) != "" {
			eg.Content = json.RawMessage(*content)
		}
		eg.CreatedAt = parseTS(cAt)
		eg.UpdatedAt = parseTS(uAt)
		out = append(out, eg)
	}
	return out, rows.Err()
}

// FindEdgesBetween returns all edges between two entities (both directions if bothDir=true).
// Optional etype filter (""=any).
func (r *Queries) FindEdgesBetween(ctx context.Context, a, b int64, bothDir bool, etype string) ([]Edge, error) {
	sb := strings.Builder{}
	sb.WriteString(`
SELECT e.edge_id, t.name, e.from_entity_id, e.to_entity_id, e.content, e.created_at, e.updated_at
FROM edges e
JOIN edge_type_lu t ON t.id = e.etype_id
WHERE `)
	args := []any{a, b}
	if bothDir {
		sb.WriteString("(e.from_entity_id = ? AND e.to_entity_id = ?) OR (e.from_entity_id = ? AND e.to_entity_id = ?)")
		args = append(args, b, a)
	} else {
		sb.WriteString("e.from_entity_id = ? AND e.to_entity_id = ?")
	}
	if etype != "" {
		sb.WriteString(" AND t.name = ?")
		args = append(args, etype)
	}
	sb.WriteString(" ORDER BY e.updated_at DESC")

	q := sb.String()
	st, err := r.prepNamed(ctx, "q.edges.between", q)
	if err != nil {
		return nil, err
	}
	rows, err := st.QueryContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Edge
	for rows.Next() {
		var eg Edge
		var cAt, uAt *string
		var content *string
		if err := rows.Scan(&eg.EdgeID, &eg.EType, &eg.FromEntityID, &eg.ToEntityID, &content, &cAt, &uAt); err != nil {
			return nil, err
		}
		if content != nil && strings.TrimSpace(*content) != "" {
			eg.Content = json.RawMessage(*content)
		}
		eg.CreatedAt = parseTS(cAt)
		eg.UpdatedAt = parseTS(uAt)
		out = append(out, eg)
	}
	return out, rows.Err()
}
