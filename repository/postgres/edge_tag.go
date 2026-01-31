// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Params: @edge_id, @ttype, @name, @value, @content(JSON)
const tagEdgeText = `SELECT public.edge_tag_upsert(@edge_id::bigint, @ttype::text, @name::text, @value::text, @content::jsonb);`

// Param: @tag_id
const selectEdgeTagByIDText = `SELECT t.tag_id, t.edge_id, t.created_at, t.updated_at, t.ttype_name, t.content 
FROM public.get_edge_tag_by_id(@tag_id::bigint) as t;`

// Params: @edge_id, @since, @names
const edgeGetTagsText = `SELECT t.tag_id, t.created_at, t.updated_at, t.ttype_name, t.content 
FROM public.edge_get_tags(@edge_id::bigint, @since::timestamp, @names::text[]) as t;`

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

	var tid int64
	j := NewRowJob(ctx, tagEdgeText, pgx.NamedArgs{
		"edge_id": eid,
		"ttype":   string(property.PropertyType()),
		"name":    property.Name(),
		"value":   property.Value(),
		"content": string(content),
	}, func(row pgx.Row) error {
		return row.Scan(&tid)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	idstr := strconv.FormatInt(tid, 10)
	return r.FindEdgeTagById(ctx, idstr)
}

// FindEdgeTagById implements the Repository interface.
func (r *PostgresRepository) FindEdgeTagById(ctx context.Context, id string) (*dbt.EdgeTag, error) {
	tid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	var eid int64
	var c, u time.Time
	var ttype, content string
	j := NewRowJob(ctx, selectEdgeTagByIDText, pgx.NamedArgs{
		"tag_id": tid,
	}, func(row pgx.Row) error {
		return row.Scan(&tid, &eid, &c, &u, &ttype, &content)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
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
	tid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	_, err = r.removeEdgeTag(ctx, tid)
	return err
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

	var out []*dbt.EdgeTag
	j := NewRowsJob(ctx, edgeGetTagsText, pgx.NamedArgs{
		"edge_id": eid,
		"since":   ts,
		"names":   names,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var tid int64
			var c, u time.Time
			var ttype, content string

			if err := rows.Scan(&tid, &c, &u, &ttype, &content); err != nil {
				continue
			}

			tag := &dbt.EdgeTag{
				ID:        strconv.FormatInt(tid, 10),
				CreatedAt: c.In(time.UTC).Local(),
				LastSeen:  u.In(time.UTC).Local(),
				Edge:      &dbt.Edge{ID: strconv.FormatInt(eid, 10)},
			}

			if prop, err := extractOAMProperty(ttype, json.RawMessage(content)); err == nil {
				tag.Property = prop
				out = append(out, tag)
			}
		}
		return rows.Err()
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	if len(out) == 0 {
		return nil, errors.New("no tags found for entity")
	}
	return out, nil
}

// removeEdgeTag deletes a specific tag from an edge.
func (r *PostgresRepository) removeEdgeTag(ctx context.Context, tid int64) (int64, error) {
	j := NewExecJob(ctx, `DELETE FROM public.edge_tag WHERE tag_id = @tag_id`, pgx.NamedArgs{
		"tag_id": tid,
	}, func(tag pgconn.CommandTag) error {
		if tag.RowsAffected() == 0 {
			return errors.New("edge tag not found")
		}
		return nil
	})

	r.pool.Submit(j)
	return tid, j.Wait()
}
