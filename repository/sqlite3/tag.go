// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// UPSERT TAG DICTIONARY (returns tag_id) -------------------------------------
// Params: :namespace, :name, :value, :meta(JSON)
const tmplUpsertTag = `
WITH
  t AS (
    INSERT INTO tags(namespace, name, value, meta)
    VALUES (coalesce(:namespace,'default'), :name, :value, coalesce(:meta,'{}'))
    ON CONFLICT(namespace, name, coalesce(value,'∅')) DO UPDATE SET
      meta = CASE
        WHEN json_patch(tags.meta, coalesce(excluded.meta,'{}')) IS NOT tags.meta
        THEN json_patch(tags.meta, coalesce(excluded.meta,'{}'))
        ELSE tags.meta
      END,
      updated_at = CASE
        WHEN json_patch(tags.meta, coalesce(excluded.meta,'{}')) IS NOT tags.meta
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE tags.updated_at END
    WHERE json_patch(tags.meta, coalesce(excluded.meta,'{}')) IS NOT tags.meta
    RETURNING tag_id
  )
SELECT tag_id FROM t
UNION ALL
SELECT tag_id FROM tags
WHERE namespace = coalesce(:namespace,'default')
  AND name = :name
  AND coalesce(value,'∅') = coalesce(:value,'∅')
LIMIT 1;`

// TAG ENTITY (returns mapping id) --------------------------------------------
// Params: :entity_id, :namespace, :name, :value, :details(JSON)
const tmplTagEntity = `
WITH
  tid AS (
    WITH t AS (
      INSERT INTO tags(namespace, name, value, meta)
      VALUES (coalesce(:namespace,'default'), :name, :value, '{}')
      ON CONFLICT(namespace, name, coalesce(value,'∅')) DO NOTHING
      RETURNING tag_id
    )
    SELECT tag_id FROM t
    UNION ALL
    SELECT tag_id FROM tags
    WHERE namespace = coalesce(:namespace,'default')
      AND name = :name
      AND coalesce(value,'∅') = coalesce(:value,'∅')
    LIMIT 1
  ),
  map AS (
    INSERT INTO entity_tag_map(entity_id, tag_id, details)
    SELECT :entity_id, (SELECT tag_id FROM tid), coalesce(:details,'{}')
    ON CONFLICT(entity_id, tag_id) DO UPDATE SET
      details = CASE
        WHEN json_patch(entity_tag_map.details, coalesce(excluded.details,'{}')) IS NOT entity_tag_map.details
        THEN json_patch(entity_tag_map.details, coalesce(excluded.details,'{}'))
        ELSE entity_tag_map.details
      END,
      updated_at = CASE
        WHEN json_patch(entity_tag_map.details, coalesce(excluded.details,'{}')) IS NOT entity_tag_map.details
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE entity_tag_map.updated_at END
    WHERE json_patch(entity_tag_map.details, coalesce(excluded.details,'{}')) IS NOT entity_tag_map.details
    RETURNING id
  )
SELECT id FROM map
UNION ALL
SELECT id FROM entity_tag_map WHERE entity_id = :entity_id AND tag_id = (SELECT tag_id FROM tid)
LIMIT 1;`

// TAG EDGE (returns mapping id) ----------------------------------------------
// Params: :edge_id, :namespace, :name, :value, :details(JSON)
const tmplTagEdge = `
WITH
  tid AS (
    WITH t AS (
      INSERT INTO tags(namespace, name, value, meta)
      VALUES (coalesce(:namespace,'default'), :name, :value, '{}')
      ON CONFLICT(namespace, name, coalesce(value,'∅')) DO NOTHING
      RETURNING tag_id
    )
    SELECT tag_id FROM t
    UNION ALL
    SELECT tag_id FROM tags
    WHERE namespace = coalesce(:namespace,'default')
      AND name = :name
      AND coalesce(value,'∅') = coalesce(:value,'∅')
    LIMIT 1
  ),
  map AS (
    INSERT INTO edge_tag_map(edge_id, tag_id, details)
    SELECT :edge_id, (SELECT tag_id FROM tid), coalesce(:details,'{}')
    ON CONFLICT(edge_id, tag_id) DO UPDATE SET
      details = CASE
        WHEN json_patch(edge_tag_map.details, coalesce(excluded.details,'{}')) IS NOT edge_tag_map.details
        THEN json_patch(edge_tag_map.details, coalesce(excluded.details,'{}'))
        ELSE edge_tag_map.details
      END,
      updated_at = CASE
        WHEN json_patch(edge_tag_map.details, coalesce(excluded.details,'{}')) IS NOT edge_tag_map.details
        THEN strftime('%Y-%m-%d %H:%M:%f','now') ELSE edge_tag_map.updated_at END
    WHERE json_patch(edge_tag_map.details, coalesce(excluded.details,'{}')) IS NOT edge_tag_map.details
    RETURNING id
  )
SELECT id FROM map
UNION ALL
SELECT id FROM edge_tag_map WHERE edge_id = :edge_id AND tag_id = (SELECT tag_id FROM tid)
LIMIT 1;`

type Tag struct {
	TagID     int64           `json:"tag_id"`
	Namespace string          `json:"namespace"`
	Name      string          `json:"name"`
	Value     *string         `json:"value,omitempty"`
	Meta      json.RawMessage `json:"meta,omitempty"`
	UpdatedAt *time.Time      `json:"updated_at,omitempty"`
}

type TagAssignment struct {
	ID        int64           `json:"id"`
	Tag       Tag             `json:"tag"`
	Details   json.RawMessage `json:"details,omitempty"`
	UpdatedAt *time.Time      `json:"updated_at,omitempty"`
}

func (s *Statements) UpsertTag(ctx context.Context, ns, name, value, metaJSON string) (int64, error) {
	row := s.UpsertTagStmt.QueryRowContext(ctx,
		sql.Named("namespace", ns),
		sql.Named("name", name),
		sql.Named("value", value),
		sql.Named("meta", metaJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (s *Statements) TagEntity(ctx context.Context, entityID int64, ns, name, value, detailsJSON string) (int64, error) {
	row := s.TagEntityStmt.QueryRowContext(ctx,
		sql.Named("entity_id", entityID),
		sql.Named("namespace", ns),
		sql.Named("name", name),
		sql.Named("value", value),
		sql.Named("details", detailsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

func (s *Statements) TagEdge(ctx context.Context, edgeID int64, ns, name, value, detailsJSON string) (int64, error) {
	row := s.TagEdgeStmt.QueryRowContext(ctx,
		sql.Named("edge_id", edgeID),
		sql.Named("namespace", ns),
		sql.Named("name", name),
		sql.Named("value", value),
		sql.Named("details", detailsJSON),
	)
	var id int64
	return id, row.Scan(&id)
}

// TagsForEntity lists all tag assignments for an entity (namespaced).
func (r *Queries) TagsForEntity(ctx context.Context, entityID int64) ([]TagAssignment, error) {
	const q = `
SELECT m.id, tg.tag_id, tg.namespace, tg.name, tg.value, tg.meta, m.details, m.updated_at, tg.updated_at
FROM entity_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.entity_id = ?
ORDER BY m.updated_at DESC`
	st, err := r.prepNamed(ctx, "q.tags.forEntity", q)
	if err != nil {
		return nil, err
	}
	rows, err := st.QueryContext(ctx, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TagAssignment
	for rows.Next() {
		var ta TagAssignment
		var mUp, tUp *string
		var v *string
		var meta, det *string
		if err := rows.Scan(
			&ta.ID,
			&ta.Tag.TagID, &ta.Tag.Namespace, &ta.Tag.Name, &v, &meta, &det, &mUp, &tUp,
		); err != nil {
			return nil, err
		}
		ta.Tag.Value = v
		if meta != nil && strings.TrimSpace(*meta) != "" {
			ta.Tag.Meta = json.RawMessage(*meta)
		}
		if det != nil && strings.TrimSpace(*det) != "" {
			ta.Details = json.RawMessage(*det)
		}
		ta.UpdatedAt = parseTS(mUp)
		ta.Tag.UpdatedAt = parseTS(tUp)
		out = append(out, ta)
	}
	return out, rows.Err()
}

// TagsForEdge lists all tags assigned to an edge.
func (r *Queries) TagsForEdge(ctx context.Context, edgeID int64) ([]TagAssignment, error) {
	const q = `
SELECT m.id, tg.tag_id, tg.namespace, tg.name, tg.value, tg.meta, m.details, m.updated_at, tg.updated_at
FROM edge_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.edge_id = ?
ORDER BY m.updated_at DESC`
	st, err := r.prepNamed(ctx, "q.tags.forEdge", q)
	if err != nil {
		return nil, err
	}
	rows, err := st.QueryContext(ctx, edgeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TagAssignment
	for rows.Next() {
		var ta TagAssignment
		var mUp, tUp *string
		var v *string
		var meta, det *string
		if err := rows.Scan(
			&ta.ID,
			&ta.Tag.TagID, &ta.Tag.Namespace, &ta.Tag.Name, &v, &meta, &det, &mUp, &tUp,
		); err != nil {
			return nil, err
		}
		ta.Tag.Value = v
		if meta != nil && strings.TrimSpace(*meta) != "" {
			ta.Tag.Meta = json.RawMessage(*meta)
		}
		if det != nil && strings.TrimSpace(*det) != "" {
			ta.Details = json.RawMessage(*det)
		}
		ta.UpdatedAt = parseTS(mUp)
		ta.Tag.UpdatedAt = parseTS(tUp)
		out = append(out, ta)
	}
	return out, rows.Err()
}

// EntitiesByTag finds entities that have a tag (namespace, name, optional value).
// If value is nil -> any value for the tag. If non-nil and empty string, matches tags whose value is NULL/empty? We treat NULL vs "" separately.
func (r *Queries) EntitiesByTag(ctx context.Context, namespace, name string, value *string, limit int) ([]int64, error) {
	sb := strings.Builder{}
	args := []any{namespace, name}
	sb.WriteString(`
SELECT m.entity_id
FROM tags tg
JOIN entity_tag_map m ON m.tag_id = tg.tag_id
WHERE tg.namespace = ? AND tg.name = ?`)
	if value != nil {
		sb.WriteString(" AND COALESCE(tg.value,'∅') = COALESCE(?, '∅')")
		args = append(args, *value)
	}
	sb.WriteString(" ORDER BY m.updated_at DESC")
	if limit > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
	}
	q := sb.String()
	st, err := r.prepNamed(ctx, "q.entities.byTag", q)
	if err != nil {
		return nil, err
	}

	rows, err := st.QueryContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// RemoveEntityTag deletes a specific tag mapping from an entity.
// If ns/name/value is nil/empty, it removes all mappings for that namespace+name (or all for the entity if both blank).
func (r *Queries) RemoveEntityTag(ctx context.Context, entityID int64, ns, name string, value *string) (rows int64, err error) {
	sb := strings.Builder{}
	args := []any{entityID}
	sb.WriteString(`
DELETE FROM entity_tag_map
WHERE entity_id = ? AND tag_id IN (
  SELECT tag_id FROM tags WHERE 1=1`)
	if ns != "" {
		sb.WriteString(" AND namespace=?")
		args = append(args, ns)
	}
	if name != "" {
		sb.WriteString(" AND name=?")
		args = append(args, name)
	}
	if value != nil {
		sb.WriteString(" AND COALESCE(value,'∅') = COALESCE(?, '∅')")
		args = append(args, *value)
	}
	sb.WriteString(")")
	q := sb.String()
	res, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RemoveEdgeTag deletes a specific tag mapping from an edge.
func (r *Queries) RemoveEdgeTag(ctx context.Context, edgeID int64, ns, name string, value *string) (int64, error) {
	sb := strings.Builder{}
	args := []any{edgeID}
	sb.WriteString(`
DELETE FROM edge_tag_map
WHERE edge_id = ? AND tag_id IN (
  SELECT tag_id FROM tags WHERE 1=1`)
	if ns != "" {
		sb.WriteString(" AND namespace=?")
		args = append(args, ns)
	}
	if name != "" {
		sb.WriteString(" AND name=?")
		args = append(args, name)
	}
	if value != nil {
		sb.WriteString(" AND COALESCE(value,'∅') = COALESCE(?, '∅')")
		args = append(args, *value)
	}
	sb.WriteString(")")
	q := sb.String()
	res, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
