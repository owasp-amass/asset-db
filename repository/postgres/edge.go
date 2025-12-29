// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// Params: @etype_name, @label, @from_entity_id, @to_entity_id, @content(JSON)
// Returns: edge_id
const edgeUpsertText = `SELECT public.edge_upsert(@etype::text, @label::text, @from::bigint, @to::bigint, @content::jsonb);`

// Params: edge_id
const selectEdgeByIDText = `
SELECT e.edge_id, e.created_at, e.updated_at, t.name, e.from_entity_id, e.to_entity_id, e.content
FROM public.edge e
JOIN public.edge_type_lu t ON t.id = e.etype_id
WHERE e.edge_id = @edge_id;`

const edgesForEntityText = `SELECT e.edge_id, e.created_at, e.updated_at, e.etype_name, e.from_entity_id, e.to_entity_id, e.label, e.content 
FROM public.edges_for_entity(@entity_id::bigint, @direction::text, @since::timestamp, @labels::text[]) as e;`

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

	var id int64
	j := NewRowJob(ctx, edgeUpsertText, pgx.NamedArgs{
		"etype":   string(rtype),
		"label":   label,
		"from":    fromID,
		"to":      toID,
		"content": string(content),
	}, func(row pgx.Row) error {
		return row.Scan(&id)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, fmt.Errorf("failed to upsert edge: %v", err)
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
	var c, u time.Time
	var etype, raw string
	var rowid, fromid, toid int64

	j := NewRowJob(ctx, selectEdgeByIDText, pgx.NamedArgs{
		"edge_id": id,
	}, func(row pgx.Row) error {
		return row.Scan(&rowid, &c, &u, &etype, &fromid, &toid, &raw)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
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
	if dir != "in" && dir != "out" && dir != "both" {
		return nil, fmt.Errorf("invalid direction: %s", dir)
	}

	if !since.IsZero() {
		since = since.UTC()
	}
	ts := zeronull.Timestamp(since)

	if len(labels) == 0 {
		labels = nil
	}

	var out []*dbt.Edge
	j := NewRowsJob(ctx, edgesForEntityText, pgx.NamedArgs{
		"entity_id": eid,
		"direction": dir,
		"since":     ts,
		"labels":    labels,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var c, u time.Time
			var etype, label, raw string
			var rowid, fromid, toid int64

			if err := rows.Scan(&rowid, &c, &u,
				&etype, &fromid, &toid, &label, &raw); err != nil {
				continue
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

			if !edge.CreatedAt.IsZero() && !edge.LastSeen.IsZero() {
				out = append(out, edge)
			}
		}
		return rows.Err()
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("zero edges found for entity %d", eid)
	}
	return out, nil
}

// deleteEdgeByID removes a single edge and cascades its tag mappings (if FK CASCADE present).
func (r *PostgresRepository) deleteEdgeByID(ctx context.Context, id int64) error {
	j := NewExecJob(ctx, `DELETE FROM edge WHERE edge_id = @edge_id`, pgx.NamedArgs{
		"edge_id": id,
	}, func(tag pgconn.CommandTag) error {
		if tag.RowsAffected() == 0 {
			return errors.New("edge not found")
		}
		return nil
	})

	r.pool.Submit(j)
	return j.Wait()
}
