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
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
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

func (r *sqliteRepository) CreateEdge(ctx context.Context, edge *types.Edge) (*types.Edge, error) {
	if edge == nil {
		return nil, fmt.Errorf("nil edge provided")
	}

	if edge.FromEntity == nil || edge.ToEntity == nil {
		return nil, fmt.Errorf("both FromEntity and ToEntity must be set")
	}

	fromID, err := strconv.ParseInt(edge.FromEntity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid FromEntity ID: %v", err)
	}

	toID, err := strconv.ParseInt(edge.ToEntity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid ToEntity ID: %v", err)
	}

	content, err := edge.Relation.JSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal edge relation to JSON: %v", err)
	}

	edgeID, err := r.stmts.EnsureEdge(ctx, string(edge.Relation.RelationType()), fromID, toID, string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to ensure edge: %v", err)
	}

	return r.FindEdgeById(ctx, fmt.Sprintf("%d", edgeID))
}

func (r *sqliteRepository) FindEdgeById(ctx context.Context, id string) (*types.Edge, error) {
	edgeID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid edge ID: %v", err)
	}

	sqlEdge, err := r.queries.FindEdgeByID(ctx, edgeID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve created edge: %v", err)
	}

	return convertSQLiteEdgeToOAMEdge(sqlEdge)
}

func convertSQLiteEdgeToOAMEdge(e *Edge) (*types.Edge, error) {
	if e == nil {
		return nil, fmt.Errorf("nil edge provided")
	}

	var rel oam.Relation
	switch e.EType {
	case strings.ToLower(string(oam.BasicDNSRelation)):
		var r oamdns.BasicDNSRelation
		if err := json.Unmarshal(e.Content, &r); err != nil {
			return nil, fmt.Errorf("failed to unmarshal BasicDNSRelation: %v", err)
		}
		rel = &r
	case strings.ToLower(string(oam.PortRelation)):
		var r oamgen.PortRelation
		if err := json.Unmarshal(e.Content, &r); err != nil {
			return nil, fmt.Errorf("failed to unmarshal PortRelation: %v", err)
		}
		rel = &r
	case strings.ToLower(string(oam.PrefDNSRelation)):
		var r oamdns.PrefDNSRelation
		if err := json.Unmarshal(e.Content, &r); err != nil {
			return nil, fmt.Errorf("failed to unmarshal PrefDNSRelation: %v", err)
		}
		rel = &r
	case strings.ToLower(string(oam.SimpleRelation)):
		var r oamgen.SimpleRelation
		if err := json.Unmarshal(e.Content, &r); err != nil {
			return nil, fmt.Errorf("failed to unmarshal SimpleRelation: %v", err)
		}
		rel = &r
	case strings.ToLower(string(oam.SRVDNSRelation)):
		var r oamdns.SRVDNSRelation
		if err := json.Unmarshal(e.Content, &r); err != nil {
			return nil, fmt.Errorf("failed to unmarshal SRVDNSRelation: %v", err)
		}
		rel = &r
	default:
		return nil, fmt.Errorf("unsupported edge type: %s", e.EType)
	}

	return &types.Edge{
		ID:         fmt.Sprintf("%d", e.EdgeID),
		CreatedAt:  (*e.CreatedAt).In(time.UTC).Local(),
		LastSeen:   (*e.UpdatedAt).In(time.UTC).Local(),
		Relation:   rel,
		FromEntity: &types.Entity{ID: fmt.Sprintf("%d", e.FromEntityID)},
		ToEntity:   &types.Entity{ID: fmt.Sprintf("%d", e.ToEntityID)},
	}, nil
}

func (r *sqliteRepository) IncomingEdges(ctx context.Context, entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid entity ID: %v", err)
	}

	edges, err := r.queries.FindEdgesForEntity(ctx, eid, "in", "", since, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve incoming edges: %v", err)
	}

	var out []*types.Edge
	for _, e := range edges {
		if len(labels) > 0 {
			matched := false
			for _, l := range labels {
				if e.EType == l {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		edge, err := convertSQLiteEdgeToOAMEdge(&e.Edge)
		if err != nil {
			return nil, fmt.Errorf("failed to convert edge: %v", err)
		}
		out = append(out, edge)
	}
	return out, nil
}

func (r *sqliteRepository) OutgoingEdges(ctx context.Context, entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid entity ID: %v", err)
	}

	edges, err := r.queries.FindEdgesForEntity(ctx, eid, "out", "", since, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve outgoing edges: %v", err)
	}

	var out []*types.Edge
	for _, e := range edges {
		if len(labels) > 0 {
			matched := false
			for _, l := range labels {
				if e.EType == l {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		edge, err := convertSQLiteEdgeToOAMEdge(&e.Edge)
		if err != nil {
			return nil, fmt.Errorf("failed to convert edge: %v", err)
		}
		out = append(out, edge)
	}
	return out, nil
}

func (r *sqliteRepository) DeleteEdge(ctx context.Context, id string) error {
	edgeID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid edge ID: %v", err)
	}
	return r.queries.DeleteEdgeByID(ctx, edgeID)
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
	defer func() { _ = rows.Close() }()

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
	defer func() { _ = rows.Close() }()

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

// DeleteEdgeByID removes a single edge and cascades its tag mappings (if FK CASCADE present).
func (r *Queries) DeleteEdgeByID(ctx context.Context, edgeID int64) error {
	const key = "del.edge.byID"
	const q = `DELETE FROM edges WHERE edge_id = ?`
	st, err := r.getOrPrepare(ctx, key, q)
	if err != nil {
		return err
	}
	res, err := st.ExecContext(ctx, edgeID) // direct exec is fine; same q
	if err != nil {
		return err
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteEdgesBetween deletes edges from a->b; if bothDir is true, also b->a.
// If etype is non-empty, limits deletion to that edge type.
// Returns the number of rows deleted.
func (r *Queries) DeleteEdgesBetween(ctx context.Context, a, b int64, bothDir bool, etype string) (int64, error) {
	args := []any{a, b}
	sb := strings.Builder{}
	sb.WriteString(`DELETE FROM edges WHERE (from_entity_id=? AND to_entity_id=?)`)
	if bothDir {
		sb.WriteString(` OR (from_entity_id=? AND to_entity_id=?)`)
		args = append(args, b, a)
	}
	if etype != "" {
		// Restrict by edge type name through a subquery match on etype_id.
		sb.WriteString(` AND etype_id = (SELECT id FROM edge_type_lu WHERE name = ?)`)
		args = append(args, etype)
	}
	q := sb.String()
	res, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteEdgesForEntity deletes incident edges to/from an entity.
// dir="out","in","" (both). Optional etype filter. Returns deleted count.
func (r *Queries) DeleteEdgesForEntity(ctx context.Context, entityID int64, dir string, etype string) (int64, error) {
	var cond string
	args := []any{entityID}
	switch strings.ToLower(strings.TrimSpace(dir)) {
	case "out":
		cond = "from_entity_id = ?"
	case "in":
		cond = "to_entity_id = ?"
	default:
		cond = "(from_entity_id = ? OR to_entity_id = ?)"
		args = append(args, entityID)
	}
	sb := strings.Builder{}
	sb.WriteString(`DELETE FROM edges WHERE ` + cond)
	if etype != "" {
		sb.WriteString(` AND etype_id = (SELECT id FROM edge_type_lu WHERE name = ?)`)
		args = append(args, etype)
	}
	q := sb.String()
	res, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
