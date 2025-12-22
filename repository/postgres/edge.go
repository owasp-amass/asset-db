// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	_ "github.com/jackc/pgx/v5/stdlib"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// Params: @etype_name, @label, @from_entity_id, @to_entity_id, @content(JSON)
// Returns: edge_id
const ensureEdgeText = `SELECT public.edge_upsert(@etype_name::text, @label::text, @from_entity_id::bigint, @to_entity_id::bigint, @content::jsonb);`

// Params: edge_id
const selectEdgeByIDText = `
SELECT e.edge_id, e.created_at, e.updated_at, t.name, e.from_entity_id, e.to_entity_id, e.content
FROM public.edge e
JOIN public.edge_type_lu t ON t.id = e.etype_id
WHERE e.edge_id = @edge_id;`

const edgesForEntityText = `SELECT public.edges_for_entity(@entity_id::bigint, @direction::text, @since::timestamp, @labels::text[]);`

func (r *PostgresRepository) CreateEdge(ctx context.Context, edge *dbt.Edge) (*dbt.Edge, error) {
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

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "edge.upsert",
		SQLText: ensureEdgeText,
		Args: pgx.NamedArgs{
			"etype_name":     string(rtype),
			"label":          label,
			"from_entity_id": fromID,
			"to_entity_id":   toID,
			"content":        string(content),
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

func (r *PostgresRepository) FindEdgeById(ctx context.Context, id string) (*dbt.Edge, error) {
	eid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid edge ID: %v", err)
	}

	return r.idToEdge(ctx, eid)
}

func (r *PostgresRepository) idToEdge(ctx context.Context, id int64) (*dbt.Edge, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "edge.by_id",
		SQLText: selectEdgeByIDText,
		Args:    pgx.NamedArgs{"edge_id": id},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var c, u time.Time
	var etype, raw string
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
		CreatedAt:  c.In(time.UTC).Local(),
		LastSeen:   u.In(time.UTC).Local(),
		Relation:   rel,
		FromEntity: &dbt.Entity{ID: strconv.FormatInt(fromid, 10)},
		ToEntity:   &dbt.Entity{ID: strconv.FormatInt(toid, 10)},
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

func (r *PostgresRepository) IncomingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid entity ID: %v", err)
	}

	return r.findEdgesForEntity(ctx, eid, "in", since, labels...)
}

func (r *PostgresRepository) OutgoingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid entity ID: %v", err)
	}

	return r.findEdgesForEntity(ctx, eid, "out", since, labels...)
}

func (r *PostgresRepository) DeleteEdge(ctx context.Context, id string) error {
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
func (r *PostgresRepository) findEdgesForEntity(ctx context.Context, eid int64, dir string, since time.Time, labels ...string) ([]*dbt.Edge, error) {
	if !since.IsZero() {
		since = since.UTC()
	}
	ts := zeronull.Timestamp(since)

	if values, vargs := inClause(labels); values != "" && len(vargs) > 0 {
		name += fmt.Sprintf(".labels%d", len(vargs))
		where = append(where, "e.label IN "+values)
		for k, v := range vargs {
			args[k] = v
		}
	}

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "edge.for_entity",
		SQLText: edgesForEntityText,
		Args: pgx.NamedArgs{
			"entity_id": eid,
			"direction": dir,
			"since":     ts,
			"labels":    labels,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.Edge
	for result.Rows.Next() {
		var c, u time.Time
		var etype, raw string
		var rowid, fromid, toid int64

		if err := result.Rows.Scan(&rowid, c, u, &etype, &fromid, &toid, &raw); err != nil {
			return nil, err
		}

		rel, err := extractOAMRelation(etype, json.RawMessage(raw))
		if err != nil {
			continue
		}

		edge := &dbt.Edge{
			ID:         strconv.FormatInt(rowid, 10),
			CreatedAt:  c.In(time.UTC).Local(),
			LastSeen:   u.In(time.UTC).Local(),
			Relation:   rel,
			FromEntity: &dbt.Entity{ID: strconv.FormatInt(fromid, 10)},
			ToEntity:   &dbt.Entity{ID: strconv.FormatInt(toid, 10)},
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
func (r *PostgresRepository) deleteEdgeByID(ctx context.Context, id int64) error {
	done := make(chan error, 1)

	r.wpool.Submit(&execJob{
		Ctx:     ctx,
		Name:    "edge.del.by_id",
		SQLText: `DELETE FROM edge WHERE edge_id = @edge_id`,
		Args:    pgx.NamedArgs{"edge_id": id},
		Result:  done,
	})

	return <-done
}
