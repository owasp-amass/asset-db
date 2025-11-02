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
	"slices"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// Params: :etype_name, :label, :from_entity_id, :to_entity_id, :content(JSON)
const ensureEdgeText = `
INSERT INTO edge(etype_id, label, from_entity_id, to_entity_id, content)
VALUES ((SELECT id FROM edge_type_lu WHERE name = lower(:etype_name) LIMIT 1), 
	lower(:label), :from_entity_id, :to_entity_id, coalesce(:content, '{}'))
ON CONFLICT(etype_id, from_entity_id, to_entity_id, label) DO UPDATE SET
    content = CASE
        WHEN json_patch(edge.content, coalesce(excluded.content, '{}')) IS NOT edge.content
        THEN json_patch(edge.content, coalesce(excluded.content, '{}'))
        ELSE edge.content
    END,
    updated_at = CURRENT_TIMESTAMP`

// Params: :etype_name, :label, :from_entity_id, :to_entity_id
const selectEdgeIDBetweenText = `
SELECT e.edge_id
FROM edge e
JOIN edge_type_lu t ON t.id = e.etype_id
WHERE t.name = lower(:etype_name)
  AND e.label = lower(:label) 
  AND e.from_entity_id = :from_entity_id
  AND e.to_entity_id = :to_entity_id`

// Params: edge_id
const selectEdgeByIDText = `
SELECT e.edge_id, e.created_at, e.updated_at, t.name, e.from_entity_id, e.to_entity_id, e.content
FROM edge e
JOIN edge_type_lu t ON t.id = e.etype_id
WHERE e.edge_id = :edge_id`

type Edge struct {
	EdgeID       int64           `json:"edge_id"`
	EType        string          `json:"etype"` // edge_type_lu.name
	FromEntityID int64           `json:"from_entity_id"`
	ToEntityID   int64           `json:"to_entity_id"`
	Content      json.RawMessage `json:"content,omitempty"` // edge.content
	CreatedAt    *time.Time      `json:"created_at,omitempty"`
	UpdatedAt    *time.Time      `json:"updated_at,omitempty"`
}

type EdgeWithTypes struct {
	Edge
	FromType string `json:"from_type"`
	ToType   string `json:"to_type"`
}

func (r *SqliteRepository) CreateEdge(ctx context.Context, edge *types.Edge) (*types.Edge, error) {
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

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "edge.upsert",
		SQLText: ensureEdgeText,
		Args: []any{
			sql.Named("etype_name", string(edge.Relation.RelationType())),
			sql.Named("label", edge.Relation.Label()),
			sql.Named("from_entity_id", fromID),
			sql.Named("to_entity_id", toID),
			sql.Named("content", string(content)),
		},
		Result: done,
	})
	err = <-done
	if err != nil {
		return nil, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "edge.id_between",
		SQLText: selectEdgeIDBetweenText,
		Args: []any{
			sql.Named("etype_name", string(edge.Relation.RelationType())),
			sql.Named("label", edge.Relation.Label()),
			sql.Named("from_entity_id", fromID),
			sql.Named("to_entity_id", toID),
		},
		Result: ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var id int64
	if err := result.Row.Scan(&id); err != nil {
		return nil, err
	}

	sqlEdge, err := r.idToEdge(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve created edge: %v", err)
	}

	return convertSQLiteEdgeToOAMEdge(sqlEdge)
}

func (r *SqliteRepository) FindEdgeById(ctx context.Context, id string) (*types.Edge, error) {
	edgeID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid edge ID: %v", err)
	}

	sqlEdge, err := r.idToEdge(ctx, edgeID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve created edge: %v", err)
	}

	return convertSQLiteEdgeToOAMEdge(sqlEdge)
}

func (r *SqliteRepository) idToEdge(ctx context.Context, id int64) (*Edge, error) {
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "edge.by_id",
		SQLText: selectEdgeByIDText,
		Args:    []any{sql.Named("edge_id", id)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var eg Edge
	var cAt, uAt *string
	var content *string
	if err := result.Row.Scan(&eg.EdgeID, &cAt, &uAt, &eg.EType,
		&eg.FromEntityID, &eg.ToEntityID, &content); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("edge %d not found", id)
		}
		return nil, err
	}

	if content != nil && strings.TrimSpace(*content) != "" {
		eg.Content = json.RawMessage(*content)
	}

	eg.CreatedAt = parseTS(cAt)
	eg.UpdatedAt = parseTS(uAt)
	if eg.CreatedAt == nil || eg.UpdatedAt == nil {
		return nil, fmt.Errorf("failed to obtain the timestamps for edge %d", id)
	}

	return &eg, nil
}

func convertSQLiteEdgeToOAMEdge(e *Edge) (*types.Edge, error) {
	if e == nil {
		return nil, fmt.Errorf("nil edge provided")
	}

	var rel oam.Relation
	switch strings.ToLower(e.EType) {
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
		CreatedAt:  e.CreatedAt.In(time.UTC).Local(),
		LastSeen:   e.UpdatedAt.In(time.UTC).Local(),
		Relation:   rel,
		FromEntity: &types.Entity{ID: fmt.Sprintf("%d", e.FromEntityID)},
		ToEntity:   &types.Entity{ID: fmt.Sprintf("%d", e.ToEntityID)},
	}, nil
}

func (r *SqliteRepository) IncomingEdges(ctx context.Context, entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid entity ID: %v", err)
	}

	edges, err := r.findEdgesForEntity(ctx, eid, "in", "", since, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve incoming edges: %v", err)
	}

	var out []*types.Edge
	for _, e := range edges {
		edge, err := convertSQLiteEdgeToOAMEdge(&e.Edge)
		if err != nil {
			return nil, fmt.Errorf("failed to convert edge: %v", err)
		}

		if len(labels) > 0 && !slices.Contains(labels, edge.Relation.Label()) {
			continue
		}

		out = append(out, edge)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no incoming edges found for entity %s", entity.ID)
	}
	return out, nil
}

func (r *SqliteRepository) OutgoingEdges(ctx context.Context, entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid entity ID: %v", err)
	}

	edges, err := r.findEdgesForEntity(ctx, eid, "out", "", since, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve outgoing edges: %v", err)
	}

	var out []*types.Edge
	for _, e := range edges {
		edge, err := convertSQLiteEdgeToOAMEdge(&e.Edge)
		if err != nil {
			return nil, fmt.Errorf("failed to convert edge: %v", err)
		}

		if len(labels) > 0 && !slices.Contains(labels, edge.Relation.Label()) {
			continue
		}

		out = append(out, edge)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no outgoing edges found for entity %s", entity.ID)
	}
	return out, nil
}

func (r *SqliteRepository) DeleteEdge(ctx context.Context, id string) error {
	eid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid edge ID: %v", err)
	}
	return r.deleteEdgeByID(ctx, eid)
}

// findEdgesForEntity returns edges incident to entityID.
// dir = "out", "in", or "" (both). etype optional ("" = any).
// since limits by updated_at >= since (zero time => no limit).
// limit <= 0 => no explicit LIMIT.
func (r *SqliteRepository) findEdgesForEntity(ctx context.Context, entityID int64, dir, etype string, since time.Time, limit int) ([]EdgeWithTypes, error) {
	base := `
SELECT e.edge_id, te.name, e.from_entity_id, e.to_entity_id, e.content, 
	e.created_at, e.updated_at, tf.name AS from_type, tt.name AS to_type
FROM edge e
JOIN edge_type_lu te ON te.id = e.etype_id
JOIN entity a ON a.entity_id = e.from_entity_id
JOIN entity b ON b.entity_id = e.to_entity_id
JOIN entity_type_lu tf ON tf.id = a.type_id
JOIN entity_type_lu tt ON tt.id = b.type_id
`
	var args []any
	var name string
	var where []string
	switch strings.ToLower(strings.TrimSpace(dir)) {
	case "out":
		name = "edge.outgoing"
		where = append(where, "e.from_entity_id = ?")
		args = append(args, entityID)
	case "in":
		name = "edge.incoming"
		where = append(where, "e.to_entity_id = ?")
		args = append(args, entityID)
	default:
		name = "edge.both"
		where = append(where, "(e.from_entity_id = ? OR e.to_entity_id = ?)")
		args = append(args, entityID, entityID)
	}
	if etype = strings.TrimSpace(etype); etype != "" {
		name += ".etype"
		where = append(where, "te.name = ?")
		args = append(args, strings.ToLower(etype))
	}
	if !since.IsZero() {
		name += ".since"
		where = append(where, "e.updated_at >= ?")
		// Use the same format parseTS() expects
		args = append(args, since.UTC().Format("2006-01-02 15:04:05.000"))
	}
	q := base + " WHERE " + strings.Join(where, " AND ") + " ORDER BY e.updated_at DESC"

	if limit > 0 {
		name += fmt.Sprintf(".limit%d", limit)
		q += fmt.Sprintf(" LIMIT %d", limit)
	}

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{
		Ctx:     ctx,
		Name:    name,
		SQLText: q,
		Args:    args,
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	var out []EdgeWithTypes
	for result.Rows.Next() {
		var eg EdgeWithTypes
		var cAt, uAt *string
		var content *string

		if err := result.Rows.Scan(&eg.EdgeID, &eg.EType, &eg.FromEntityID,
			&eg.ToEntityID, &content, &cAt, &uAt, &eg.FromType, &eg.ToType); err != nil {
			return nil, err
		}

		if content != nil && strings.TrimSpace(*content) != "" {
			eg.Content = json.RawMessage(*content)
		}

		eg.CreatedAt = parseTS(cAt)
		eg.UpdatedAt = parseTS(uAt)
		if eg.CreatedAt == nil || eg.UpdatedAt == nil {
			continue
		}

		out = append(out, eg)
	}

	return out, result.Rows.Err()
}

// deleteEdgeByID removes a single edge and cascades its tag mappings (if FK CASCADE present).
func (r *SqliteRepository) deleteEdgeByID(ctx context.Context, id int64) error {
	done := make(chan error, 1)

	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "edge.del.by_id",
		SQLText: `DELETE FROM edge WHERE edge_id = :edge_id`,
		Args:    []any{sql.Named("edge_id", id)},
		Result:  done,
	})

	return <-done
}
