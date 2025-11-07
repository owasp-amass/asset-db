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
	"time"

	_ "github.com/mattn/go-sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Params: :edge_id, :tag_id
const tagEdgeText = `
INSERT INTO edge_tag_map(edge_id, tag_id)
VALUES (:edge_id, :tag_id)
ON CONFLICT(edge_id, tag_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP`

// Params: :edge_id, :tag_id
const selectEdgeTagMapIDText = `
SELECT id FROM edge_tag_map
WHERE edge_id = :edge_id AND tag_id = :tag_id 
LIMIT 1`

func (r *SqliteRepository) CreateEdgeTag(ctx context.Context, edge *dbt.Edge, tag *dbt.EdgeTag) (*dbt.EdgeTag, error) {
	return r.CreateEdgeProperty(ctx, edge, tag.Property)
}

func (r *SqliteRepository) CreateEdgeProperty(ctx context.Context, edge *dbt.Edge, property oam.Property) (*dbt.EdgeTag, error) {
	content, err := property.JSON()
	if err != nil {
		return nil, err
	}

	tid, err := r.upsertTag(ctx, string(property.PropertyType()), property.Name(), property.Value(), string(content))
	if err != nil {
		return nil, err
	}

	eid, err := strconv.ParseInt(edge.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	mid, err := r.tagEdge(ctx, eid, tid)
	if err != nil {
		return nil, err
	}

	idstr := strconv.FormatInt(mid, 10)
	return r.FindEdgeTagById(ctx, idstr)
}

// FindEdgeTagById implements the Repository interface.
func (r *SqliteRepository) FindEdgeTagById(ctx context.Context, id string) (*dbt.EdgeTag, error) {
	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	const q = `
SELECT m.id, m.edge_id, m.created_at, m.updated_at, tt.name, tg.content
FROM edge_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
JOIN tag_type_lu tt ON tt.id = tg.ttype_id
WHERE m.id = :map_id
LIMIT 1`

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "edge.tag.by_id",
		SQLText: q,
		Args:    []any{sql.Named("map_id", mid)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var eid, row_id int64
	var ttype, content, c, u string
	if err := result.Row.Scan(&row_id, &eid, &c, &u, &ttype, &content); err != nil {
		return nil, err
	}

	tag := &dbt.EdgeTag{
		ID:   strconv.FormatInt(row_id, 10),
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

func (r *SqliteRepository) tagEdge(ctx context.Context, edgeID, tagID int64) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "edge.tag.upsert_edge_tag_mapping",
		SQLText: tagEdgeText,
		Args: []any{
			sql.Named("edge_id", edgeID),
			sql.Named("tag_id", tagID),
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
		Name:    "edge.tag.edge_tag_mapping_id_by_ids",
		SQLText: selectEdgeTagMapIDText,
		Args: []any{
			sql.Named("edge_id", edgeID),
			sql.Named("tag_id", tagID),
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
SELECT m.id, m.created_at, m.updated_at, tt.name, tg.content
FROM edge_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
JOIN tag_type_lu tt ON tt.id = tg.ttype_id
WHERE m.edge_id = :edge_id`

	if !since.IsZero() {
		key += ".since"
		q += " AND m.updated_at >= :since"
		args = append(args, sql.Named("since", since.UTC()))
	}
	if values, vargs := inClause(names); values != "" && len(vargs) > 0 {
		key += fmt.Sprintf(".names%d", len(vargs))
		q += " AND tg.property_name IN " + values
		args = append(args, vargs...)
	}

	q += " ORDER BY m.updated_at DESC"

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
		var row_id int64
		var ttype, content, c, u string

		if err := result.Rows.Scan(&row_id, &c, &u, &ttype, &content); err != nil {
			return nil, err
		}

		tag := &dbt.EdgeTag{
			ID:   strconv.FormatInt(row_id, 10),
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

// removeEdgeTag deletes a specific tag mapping from an edge.
func (r *SqliteRepository) removeEdgeTag(ctx context.Context, mid int64) (int64, error) {
	tid, err := r.edgeMIDToTID(ctx, mid)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "edge.tag.remove_edge_tag",
		SQLText: `DELETE FROM edge_tag_map WHERE id = :map_id`,
		Args:    []any{sql.Named("map_id", mid)},
		Result:  done,
	})

	return tid, <-done
}

func (r *SqliteRepository) edgeMIDToTID(ctx context.Context, mid int64) (int64, error) {
	const q = `
SELECT tg.tag_id
FROM edge_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
WHERE m.id = :map_id
ORDER BY m.updated_at DESC
LIMIT 1`

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "edge.tag.mid_to_tid",
		SQLText: q,
		Args:    []any{sql.Named("map_id", mid)},
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
