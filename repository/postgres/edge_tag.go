// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Params: @edge_id, @ttype, @name, @value, @content(JSON)
const tagEdgeText = `SELECT public.edge_tag_map_upsert(@edge_id::bigint, @ttype::text, @name::text, @value::text, @content::jsonb);`

// Param: @map_id
const selectEdgeTagMapByIDText = `SELECT public.get_edge_tag_map_by_id(@map_id::bigint);`

// Params: @edge_id, @since, @names
const edgeGetTagsText = `SELECT public.edge_get_tags(@edge_id::bigint, @since::timestamp, @names::text[]);`

// Param: @map_id
const selectTagIDByEdgeTagMapIDText = `SELECT public.edge_tag_map_get_tag_id(@map_id::bigint);`

func (r *PostgresRepository) CreateEdgeTag(ctx context.Context, edge *dbt.Edge, tag *dbt.EdgeTag) (*dbt.EdgeTag, error) {
	return r.CreateEdgeProperty(ctx, edge, tag.Property)
}

func (r *PostgresRepository) CreateEdgeProperty(ctx context.Context, edge *dbt.Edge, property oam.Property) (*dbt.EdgeTag, error) {
	content, err := property.JSON()
	if err != nil {
		return nil, err
	}

	eid, err := strconv.ParseInt(edge.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "edge.tag.upsert",
		SQLText: tagEdgeText,
		Args: pgx.NamedArgs{
			"edge_id": eid,
			"ttype":   string(property.PropertyType()),
			"name":    property.Name(),
			"value":   property.Value(),
			"content": string(content),
		},
		Result: ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var tid, mid int64
	if err := result.Row.Scan(&tid, &mid); err != nil {
		return nil, err
	}

	idstr := strconv.FormatInt(mid, 10)
	return r.FindEdgeTagById(ctx, idstr)
}

// FindEdgeTagById implements the Repository interface.
func (r *PostgresRepository) FindEdgeTagById(ctx context.Context, id string) (*dbt.EdgeTag, error) {
	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "edge.tag.by_id",
		SQLText: selectEdgeTagMapByIDText,
		Args:    pgx.NamedArgs{"map_id": mid},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var eid, tid int64
	var c, u time.Time
	var ttype, content string
	if err := result.Row.Scan(&tid, &eid, &c, &u, &ttype, &content); err != nil {
		return nil, err
	}

	tag := &dbt.EdgeTag{
		ID:        id,
		CreatedAt: c.In(time.UTC).Local(),
		LastSeen:  u.In(time.UTC).Local(),
		Edge:      &dbt.Edge{ID: strconv.FormatInt(eid, 10)},
	}

	prop, err := extractOAMProperty(ttype, json.RawMessage(content))
	if err != nil {
		return nil, err
	}
	tag.Property = prop

	return tag, nil
}

func (r *PostgresRepository) FindEdgeTags(ctx context.Context, edge *dbt.Edge, since time.Time, names ...string) ([]*dbt.EdgeTag, error) {
	eid, err := strconv.ParseInt(edge.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	return r.tagsForEdge(ctx, eid, since, names...)
}

func (r *PostgresRepository) DeleteEdgeTag(ctx context.Context, id string) error {
	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	tid, err := r.removeEdgeTag(ctx, mid)
	if err != nil {
		return err
	}

	return r.deleteTagByID(ctx, tid, true)
}

// tagsForEdge lists all tags assigned to an edge.
func (r *PostgresRepository) tagsForEdge(ctx context.Context, eid int64, since time.Time, names ...string) ([]*dbt.EdgeTag, error) {
	if !since.IsZero() {
		since = since.UTC()
	}
	ts := zeronull.Timestamp(since)

	if len(names) == 0 {
		names = nil
	}

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "edge.tags_for_edge",
		SQLText: edgeGetTagsText,
		Args: pgx.NamedArgs{
			"edge_id": eid,
			"since":   ts,
			"names":   names,
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

	var out []*dbt.EdgeTag
	for result.Rows.Next() {
		var tid, mid int64
		var c, u time.Time
		var ttype, content string

		if err := result.Rows.Scan(&tid, &mid, &c, &u, &ttype, &content); err != nil {
			continue
		}

		tag := &dbt.EdgeTag{
			ID:        strconv.FormatInt(mid, 10),
			CreatedAt: c.In(time.UTC).Local(),
			LastSeen:  u.In(time.UTC).Local(),
			Edge:      &dbt.Edge{ID: strconv.FormatInt(eid, 10)},
		}

		prop, err := extractOAMProperty(ttype, json.RawMessage(content))
		if err != nil {
			continue
		}
		tag.Property = prop

		out = append(out, tag)
	}

	if len(out) == 0 {
		return nil, errors.New("no tags found for entity")
	}
	return out, nil
}

// removeEdgeTag deletes a specific tag mapping from an edge.
func (r *PostgresRepository) removeEdgeTag(ctx context.Context, mid int64) (int64, error) {
	tid, err := r.edgeMIDToTID(ctx, mid)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.wpool.Submit(&execJob{
		Ctx:     ctx,
		Name:    "edge.tag.remove_edge_tag",
		SQLText: `DELETE FROM public.edge_tag_map WHERE map_id = @map_id`,
		Args:    pgx.NamedArgs{"map_id": mid},
		Result:  done,
	})

	return tid, <-done
}

func (r *PostgresRepository) edgeMIDToTID(ctx context.Context, mid int64) (int64, error) {
	if mid == 0 {
		return 0, errors.New("invalid edge tag map ID")
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "edge.tag.mid_to_tid",
		SQLText: selectTagIDByEdgeTagMapIDText,
		Args:    pgx.NamedArgs{"map_id": mid},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return 0, result.Err
	}

	var tid int64
	err := result.Row.Scan(&tid)
	return tid, err
}
