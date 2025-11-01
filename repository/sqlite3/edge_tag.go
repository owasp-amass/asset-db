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

func (r *SqliteRepository) CreateEdgeTag(ctx context.Context, edge *types.Edge, tag *types.EdgeTag) (*types.EdgeTag, error) {
	return r.CreateEdgeProperty(ctx, edge, tag.Property)
}

func (r *SqliteRepository) CreateEdgeProperty(ctx context.Context, edge *types.Edge, property oam.Property) (*types.EdgeTag, error) {
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

	tags, err := r.tagsForEdge(ctx, eid)
	if err != nil {
		return nil, err
	}

	var assignment *TagAssignment
	for _, t := range tags {
		if t.ID == mid {
			assignment = &t
			break
		}
	}
	if assignment == nil {
		return nil, fmt.Errorf("tag mapping not found after creation")
	}

	return &types.EdgeTag{
		ID:        strconv.FormatInt(mid, 10),
		CreatedAt: assignment.CreatedAt.In(time.UTC).Local(),
		LastSeen:  assignment.UpdatedAt.In(time.UTC).Local(),
		Property:  property,
		Edge:      edge,
	}, nil
}

// FindEdgeTagById implements the Repository interface.
func (r *SqliteRepository) FindEdgeTagById(ctx context.Context, id string) (*types.EdgeTag, error) {
	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	const q = `
SELECT m.id, m.edge_id, tg.tag_id, (SELECT name FROM tag_type_lu WHERE id = tg.ttype_id LIMIT 1), 
	tg.property_name, tg.property_value, tg.content, tg.updated_at, m.created_at, m.updated_at
FROM edge_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
WHERE m.id = :map_id
ORDER BY m.updated_at DESC
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

	var eid int64
	var v *string
	var meta *string
	var ta TagAssignment
	var created, updated, tupdated *string
	if err := result.Row.Scan(&ta.ID, &eid, &ta.Tag.TagID, &ta.Tag.Namespace,
		&ta.Tag.Name, &v, &meta, &tupdated, &created, &updated); err != nil {
		return nil, err
	}

	ta.Tag.Value = v
	if meta != nil && strings.TrimSpace(*meta) != "" {
		ta.Tag.Meta = json.RawMessage(*meta)
	}

	ta.CreatedAt = parseTS(created)
	ta.UpdatedAt = parseTS(updated)
	ta.Tag.UpdatedAt = parseTS(tupdated)
	if ta.CreatedAt == nil || ta.UpdatedAt == nil || ta.Tag.UpdatedAt == nil {
		return nil, errors.New("failed to obtain the timestamps")
	}

	prop, err := convertSQLitePropertyToOAMProperty(&ta)
	if err != nil {
		return nil, err
	}

	return &types.EdgeTag{
		ID:        strconv.FormatInt(ta.ID, 10),
		CreatedAt: ta.CreatedAt.In(time.UTC).Local(),
		LastSeen:  ta.UpdatedAt.In(time.UTC).Local(),
		Property:  prop,
		Edge:      &types.Edge{ID: strconv.FormatInt(eid, 10)},
	}, nil
}

func (r *SqliteRepository) FindEdgeTags(ctx context.Context, edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {
	eid, err := strconv.ParseInt(edge.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	tags, err := r.tagsForEdge(ctx, eid)
	if err != nil {
		return nil, err
	}

	var out []*types.EdgeTag
	for _, t := range tags {
		if t.UpdatedAt != nil && !since.IsZero() && t.UpdatedAt.Before(since) {
			continue
		}

		if len(names) > 0 {
			found := false
			for _, n := range names {
				if t.Tag.Name == n {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		prop, err := convertSQLitePropertyToOAMProperty(&t)
		if err != nil {
			return nil, err
		}

		out = append(out, &types.EdgeTag{
			ID:        strconv.FormatInt(t.ID, 10),
			CreatedAt: t.CreatedAt.In(time.UTC).Local(),
			LastSeen:  t.UpdatedAt.In(time.UTC).Local(),
			Property:  prop,
			Edge:      edge,
		})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no tags found for edge")
	}
	return out, nil
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
func (r *SqliteRepository) tagsForEdge(ctx context.Context, edgeID int64) ([]TagAssignment, error) {
	const q = `
SELECT m.id, tg.tag_id, (SELECT name FROM tag_type_lu WHERE id = tg.ttype_id LIMIT 1), 
	tg.property_name, tg.property_value, tg.content, tg.updated_at, m.created_at, m.updated_at
FROM edge_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
WHERE m.edge_id = :edge_id
ORDER BY m.updated_at DESC`

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{
		Ctx:     ctx,
		Name:    "edge.tag.tags_for_edge",
		SQLText: q,
		Args:    []any{sql.Named("edge_id", edgeID)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	var out []TagAssignment
	for result.Rows.Next() {
		var ta TagAssignment
		var created, updated, tupdated *string
		var v *string
		var meta *string

		if err := result.Rows.Scan(&ta.ID, &ta.Tag.TagID, &ta.Tag.Namespace,
			&ta.Tag.Name, &v, &meta, &tupdated, &created, &updated); err != nil {
			return nil, err
		}

		ta.Tag.Value = v
		if meta != nil && strings.TrimSpace(*meta) != "" {
			ta.Tag.Meta = json.RawMessage(*meta)
		}

		ta.CreatedAt = parseTS(created)
		ta.UpdatedAt = parseTS(updated)
		ta.Tag.UpdatedAt = parseTS(tupdated)
		if ta.CreatedAt == nil || ta.UpdatedAt == nil || ta.Tag.UpdatedAt == nil {
			continue
		}

		out = append(out, ta)
	}

	return out, result.Rows.Err()
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
