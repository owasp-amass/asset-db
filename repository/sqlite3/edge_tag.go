// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	_ "modernc.org/sqlite"
)

// Params: :edge_id, :ttype_name, :property_name, :property_value, :content(JSON)
const tagEdgeText = `
INSERT INTO edge_tag(edge_id, ttype_id, property_name, property_value, content)
VALUES (:edge_id, (SELECT id FROM tag_type_lu WHERE name = lower(:ttype_name) LIMIT 1), 
	:property_name, :property_value, coalesce(:content, '{}'))
ON CONFLICT(edge_id, ttype_id, property_name, property_value) DO UPDATE SET
    content = CASE
        WHEN json_patch(edge_tag.content, coalesce(excluded.content,'{}')) IS NOT edge_tag.content
          THEN json_patch(edge_tag.content, coalesce(excluded.content,'{}'))
        ELSE edge_tag.content
    END,
    updated_at = CURRENT_TIMESTAMP`

// Params: :edge_id, :ttype_name, :property_name, :property_value
const selectEdgeTagIDText = `
SELECT tag_id FROM edge_tag 
JOIN tag_type_lu tt ON tt.id = edge_tag.ttype_id
WHERE edge_tag.edge_id = :edge_id AND tt.name = lower(:ttype_name) 
  AND edge_tag.property_name = :property_name 
  AND coalesce(edge_tag.property_value,'∅') = coalesce(:property_value,'∅')
LIMIT 1`

func (r *SqliteRepository) CreateEdgeTag(ctx context.Context, edge *dbt.Edge, tag *dbt.EdgeTag) (*dbt.EdgeTag, error) {
	return r.CreateEdgeProperty(ctx, edge, tag.Property)
}

func (r *SqliteRepository) CreateEdgeProperty(ctx context.Context, edge *dbt.Edge, property oam.Property) (*dbt.EdgeTag, error) {
	content, err := property.JSON()
	if err != nil {
		return nil, err
	}

	eid, err := strconv.ParseInt(edge.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	tid, err := r.tagEdge(ctx, eid, property, string(content))
	if err != nil {
		return nil, err
	}

	idstr := strconv.FormatInt(tid, 10)
	return r.FindEdgeTagById(ctx, idstr)
}

// FindEdgeTagById implements the Repository interface.
func (r *SqliteRepository) FindEdgeTagById(ctx context.Context, id string) (*dbt.EdgeTag, error) {
	tid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	const q = `
SELECT et.tag_id, et.edge_id, et.created_at, et.updated_at, tt.name, et.content
FROM edge_tag et
JOIN tag_type_lu tt ON tt.id = et.ttype_id
WHERE et.tag_id = :tag_id
LIMIT 1`

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "edge.tag.by_id",
		SQLText: q,
		Args:    []any{sql.Named("tag_id", tid)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var eid int64
	var ttype, content, c, u string
	if err := result.Row.Scan(&tid, &eid, &c, &u, &ttype, &content); err != nil {
		return nil, err
	}

	tag := &dbt.EdgeTag{
		ID:   id,
		Edge: &dbt.Edge{ID: strconv.FormatInt(eid, 10)},
	}

	prop, err := extractOAMProperty(ttype, json.RawMessage(content))
	if err != nil {
		return nil, err
	}
	tag.Property = prop

	if c, err := parseTimestamp(c); err != nil {
		return nil, err
	} else {
		tag.CreatedAt = c.In(time.UTC).Local()
	}
	if u, err := parseTimestamp(u); err != nil {
		return nil, err
	} else {
		tag.LastSeen = u.In(time.UTC).Local()
	}

	return tag, nil
}

func (r *SqliteRepository) FindEdgeTags(ctx context.Context, edge *dbt.Edge, since time.Time, names ...string) ([]*dbt.EdgeTag, error) {
	eid, err := strconv.ParseInt(edge.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	return r.tagsForEdge(ctx, eid, since, names...)
}

func (r *SqliteRepository) DeleteEdgeTag(ctx context.Context, id string) error {
	tid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "edge.tag.delete",
		SQLText: `DELETE FROM edge_tag WHERE tag_id = :tag_id`,
		Args:    []any{sql.Named("tag_id", tid)},
		Result:  done,
	})
	return <-done
}

func (r *SqliteRepository) tagEdge(ctx context.Context, edgeID int64, property oam.Property, content string) (int64, error) {
	done := make(chan error, 1)
	ttype := string(property.PropertyType())

	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "edge.tag.upsert",
		SQLText: tagEdgeText,
		Args: []any{
			sql.Named("edge_id", edgeID),
			sql.Named("ttype_name", ttype),
			sql.Named("property_name", property.Name()),
			sql.Named("property_value", property.Value()),
			sql.Named("content", content),
		},
		Result: done,
	})
	err := <-done
	if err != nil {
		return 0, err
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "edge.tag.id_by_values",
		SQLText: selectEdgeTagIDText,
		Args: []any{
			sql.Named("edge_id", edgeID),
			sql.Named("ttype_name", ttype),
			sql.Named("property_name", property.Name()),
			sql.Named("property_value", property.Value()),
		},
		Result: ch,
	})

	result := <-ch
	if result.Err != nil {
		return 0, result.Err
	}

	var id int64
	err = result.Row.Scan(&id)
	return id, err
}

// tagsForEdge lists all tags assigned to an edge.
func (r *SqliteRepository) tagsForEdge(ctx context.Context, eid int64, since time.Time, names ...string) ([]*dbt.EdgeTag, error) {
	key := "edge.tag.tags_for_edge"
	args := []any{sql.Named("edge_id", eid)}
	q := `
SELECT et.tag_id, et.created_at, et.updated_at, tt.name, et.content
FROM edge_tag et
JOIN tag_type_lu tt ON tt.id = et.ttype_id
WHERE et.edge_id = :edge_id`

	if !since.IsZero() {
		key += ".since"
		q += " AND et.updated_at >= :since"
		args = append(args, sql.Named("since", since.UTC()))
	}
	if values, vargs := inClause(names); values != "" && len(vargs) > 0 {
		key += fmt.Sprintf(".names%d", len(vargs))
		q += " AND et.property_name IN " + values
		args = append(args, vargs...)
	}

	q += " ORDER BY et.updated_at DESC"

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{
		Ctx:     ctx,
		Name:    key,
		SQLText: q,
		Args:    args,
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	var out []*dbt.EdgeTag
	for result.Rows.Next() {
		var tid int64
		var ttype, content, c, u string

		if err := result.Rows.Scan(&tid, &c, &u, &ttype, &content); err != nil {
			return nil, err
		}

		tag := &dbt.EdgeTag{
			ID:   strconv.FormatInt(tid, 10),
			Edge: &dbt.Edge{ID: strconv.FormatInt(eid, 10)},
		}

		prop, err := extractOAMProperty(ttype, json.RawMessage(content))
		if err != nil {
			return nil, err
		}
		tag.Property = prop

		if c, err := parseTimestamp(c); err != nil {
			return nil, err
		} else {
			tag.CreatedAt = c.In(time.UTC).Local()
		}
		if u, err := parseTimestamp(u); err != nil {
			return nil, err
		} else {
			tag.LastSeen = u.In(time.UTC).Local()
		}

		out = append(out, tag)
	}

	if len(out) == 0 {
		return nil, errors.New("no tags found for edge")
	}
	return out, nil
}
