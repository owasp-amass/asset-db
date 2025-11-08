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
	dbt "github.com/owasp-amass/asset-db/types"
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

func (r *SqliteRepository) CreateEdge(ctx context.Context, edge *dbt.Edge) (*dbt.Edge, error) {
	if edge == nil {
		return nil, fmt.Errorf("nil edge provided")
	}

	if edge.Relation == nil {
		return nil, fmt.Errorf("edge relation cannot be nil")
	}

	if edge.FromEntity == nil || edge.ToEntity == nil {
		return nil, fmt.Errorf("both FromEntity and ToEntity must be set")
	}

	fromID, err := strconv.ParseInt(edge.FromEntity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid FromEntity ID: %v", err)
	}

	fromEnt, err := r.FindEntityById(ctx, edge.FromEntity.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to find FromEntity: %v", err)
	}
	fromtype := fromEnt.Asset.AssetType()

	toID, err := strconv.ParseInt(edge.ToEntity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid ToEntity ID: %v", err)
	}

	toEnt, err := r.FindEntityById(ctx, edge.ToEntity.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to find ToEntity: %v", err)
	}
	totype := toEnt.Asset.AssetType()

	label := edge.Relation.Label()
	rtype := edge.Relation.RelationType()
	if rtype == oam.PortRelation {
		label = "port"
	}

	if !oam.ValidRelationship(fromtype, label, rtype, totype) {
		return nil, fmt.Errorf("invalid relationship between %s and %s", fromtype, totype)
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
			sql.Named("etype_name", string(rtype)),
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
			sql.Named("etype_name", string(rtype)),
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

	return r.idToEdge(ctx, id)
}

func (r *SqliteRepository) FindEdgeById(ctx context.Context, id string) (*dbt.Edge, error) {
	eid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid edge ID: %v", err)
	}

	return r.idToEdge(ctx, eid)
}

func (r *SqliteRepository) idToEdge(ctx context.Context, id int64) (*dbt.Edge, error) {
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

	var c, u, etype, raw string
	var rowid, fromid, toid int64
	if err := result.Row.Scan(&rowid, &c, &u, &etype, &fromid, &toid, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("edge %d not found", id)
		}
		return nil, err
	}

	rel, err := extractOAMRelation(etype, json.RawMessage(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to extract OAM relation: %v", err)
	}

	edge := &dbt.Edge{
		ID:         strconv.FormatInt(id, 10),
		Relation:   rel,
		FromEntity: &dbt.Entity{ID: strconv.FormatInt(fromid, 10)},
		ToEntity:   &dbt.Entity{ID: strconv.FormatInt(toid, 10)},
	}

	if created, err := parseTimestamp(c); err == nil {
		edge.CreatedAt = created
	} else {
		return nil, err
	}
	if updated, err := parseTimestamp(u); err == nil {
		edge.LastSeen = updated
	} else {
		return nil, err
	}
	if edge.CreatedAt.IsZero() || edge.LastSeen.IsZero() {
		return nil, errors.New("failed to obtain the edge timestamps")
	}

	return edge, nil
}

func extractOAMRelation(etype string, content json.RawMessage) (oam.Relation, error) {
	err := errors.New("failed to extract relation from the JSON")

	if len(content) == 0 {
		return nil, err
	}

	var rel oam.Relation
	switch strings.ToLower(etype) {
	case strings.ToLower(string(oam.BasicDNSRelation)):
		var r oamdns.BasicDNSRelation
		if e := json.Unmarshal(content, &r); e == nil {
			rel = &r
			err = nil
		}
	case strings.ToLower(string(oam.PortRelation)):
		var r oamgen.PortRelation
		if e := json.Unmarshal(content, &r); e == nil {
			rel = &r
			err = nil
		}
	case strings.ToLower(string(oam.PrefDNSRelation)):
		var r oamdns.PrefDNSRelation
		if e := json.Unmarshal(content, &r); e == nil {
			rel = &r
			err = nil
		}
	case strings.ToLower(string(oam.SimpleRelation)):
		var r oamgen.SimpleRelation
		if e := json.Unmarshal(content, &r); e == nil {
			rel = &r
			err = nil
		}
	case strings.ToLower(string(oam.SRVDNSRelation)):
		var r oamdns.SRVDNSRelation
		if e := json.Unmarshal(content, &r); e == nil {
			rel = &r
			err = nil
		}
	default:
		return nil, fmt.Errorf("unsupported edge type: %s", etype)
	}

	return rel, err
}

func (r *SqliteRepository) IncomingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid entity ID: %v", err)
	}

	return r.findEdgesForEntity(ctx, eid, "in", since, labels...)
}

func (r *SqliteRepository) OutgoingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid entity ID: %v", err)
	}

	return r.findEdgesForEntity(ctx, eid, "out", since, labels...)
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
func (r *SqliteRepository) findEdgesForEntity(ctx context.Context, eid int64, dir string, since time.Time, labels ...string) ([]*dbt.Edge, error) {
	base := `
SELECT e.edge_id, te.name, e.from_entity_id, e.to_entity_id, e.content, e.created_at, e.updated_at
FROM edge e
JOIN edge_type_lu te ON te.id = e.etype_id
`
	var args []any
	var name string
	var where []string
	switch strings.ToLower(strings.TrimSpace(dir)) {
	case "out":
		name = "edge.outgoing"
		where = append(where, "e.from_entity_id = :entity_id")
		args = append(args, sql.Named("entity_id", eid))
	case "in":
		name = "edge.incoming"
		where = append(where, "e.to_entity_id = :entity_id")
		args = append(args, sql.Named("entity_id", eid))
	default:
		name = "edge.both"
		where = append(where, "(e.from_entity_id = :entity_id OR e.to_entity_id = :entity_id)")
		args = append(args, sql.Named("entity_id", eid))
	}
	if !since.IsZero() {
		name += ".since"
		where = append(where, "e.updated_at >= :since")
		args = append(args, sql.Named("since", since.UTC()))
	}
	if values, vargs := inClause(labels); values != "" && len(vargs) > 0 {
		name += fmt.Sprintf(".labels%d", len(vargs))
		where = append(where, "e.label IN "+values)
		args = append(args, vargs...)
	}

	q := base + " WHERE " + strings.Join(where, " AND ") + " ORDER BY e.updated_at DESC"

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

	var out []*dbt.Edge
	for result.Rows.Next() {
		var c, u, etype, raw string
		var rowid, fromid, toid int64

		if err := result.Rows.Scan(&rowid, &etype, &fromid, &toid, &raw, &c, &u); err != nil {
			return nil, err
		}

		rel, err := extractOAMRelation(etype, json.RawMessage(raw))
		if err != nil {
			continue
		}

		edge := &dbt.Edge{
			ID:         strconv.FormatInt(rowid, 10),
			Relation:   rel,
			FromEntity: &dbt.Entity{ID: strconv.FormatInt(fromid, 10)},
			ToEntity:   &dbt.Entity{ID: strconv.FormatInt(toid, 10)},
		}

		if created, err := parseTimestamp(c); err == nil {
			edge.CreatedAt = created
		} else {
			return nil, err
		}
		if updated, err := parseTimestamp(u); err == nil {
			edge.LastSeen = updated
		} else {
			return nil, err
		}
		if edge.CreatedAt.IsZero() || edge.LastSeen.IsZero() {
			continue
		}

		out = append(out, edge)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("zero edges found for entity %d", eid)
	}
	return out, nil
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
