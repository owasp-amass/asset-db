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
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
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
	CreatedAt *time.Time      `json:"created_at,omitempty"`
	UpdatedAt *time.Time      `json:"updated_at,omitempty"`
}

func (r *sqliteRepository) CreateEntityTag(ctx context.Context, entity *types.Entity, tag *types.EntityTag) (*types.EntityTag, error) {
	return r.CreateEntityProperty(ctx, entity, tag.Property)
}

func (r *sqliteRepository) CreateEntityProperty(ctx context.Context, entity *types.Entity, property oam.Property) (*types.EntityTag, error) {
	_, err := r.stmts.UpsertTag(ctx, string(property.PropertyType()), property.Name(), property.Value(), "{}")
	if err != nil {
		return nil, err
	}

	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	details, err := property.JSON()
	if err != nil {
		return nil, err
	}

	mid, err := r.stmts.TagEntity(ctx, eid, string(property.PropertyType()), property.Name(), property.Value(), string(details))
	if err != nil {
		return nil, err
	}

	tags, err := r.queries.TagsForEntity(ctx, eid)
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

	return &types.EntityTag{
		ID:        strconv.FormatInt(mid, 10),
		CreatedAt: (*assignment).CreatedAt.In(time.UTC).Local(),
		LastSeen:  (*assignment).UpdatedAt.In(time.UTC).Local(),
		Property:  property,
		Entity:    entity,
	}, nil
}

func (r *sqliteRepository) FindEntityTagById(ctx context.Context, id string) (*types.EntityTag, error) {
	const q = `
SELECT m.id, m.entity_id, tg.tag_id, tg.namespace, tg.name, tg.value, tg.meta, m.details, tg.updated_at, m.created_at, m.updated_at
FROM entity_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.id = ?
ORDER BY m.updated_at DESC`
	st, err := r.queries.prepNamed(ctx, "q.tags.entityTagById", q)
	if err != nil {
		return nil, err
	}

	rows, err := st.QueryContext(ctx, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	rows.Next()
	var eid int64
	var ta TagAssignment
	var created, updated, tupdated *string
	var v *string
	var meta, det *string
	if err := rows.Scan(
		&ta.ID, &eid, &ta.Tag.TagID, &ta.Tag.Namespace,
		&ta.Tag.Name, &v, &meta, &det, &created, &updated, &tupdated,
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

	return &types.EntityTag{
		ID:        strconv.FormatInt(ta.ID, 10),
		CreatedAt: ta.CreatedAt.In(time.UTC).Local(),
		LastSeen:  ta.UpdatedAt.In(time.UTC).Local(),
		Property:  prop,
		Entity:    &types.Entity{ID: strconv.FormatInt(eid, 10)},
	}, nil
}

func (r *sqliteRepository) FindEntityTags(ctx context.Context, entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	tags, err := r.queries.TagsForEntity(ctx, eid)
	if err != nil {
		return nil, err
	}

	var out []*types.EntityTag
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

		out = append(out, &types.EntityTag{
			ID:        strconv.FormatInt(t.ID, 10),
			CreatedAt: t.CreatedAt.In(time.UTC).Local(),
			LastSeen:  t.UpdatedAt.In(time.UTC).Local(),
			Property:  prop,
			Entity:    entity,
		})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no tags found for entity")
	}
	return out, nil
}

func convertSQLitePropertyToOAMProperty(ta *TagAssignment) (oam.Property, error) {
	var p oam.Property

	switch strings.ToLower(ta.Tag.Namespace) {
	case strings.ToLower(string(oam.DNSRecordProperty)):
		var dp oamdns.DNSRecordProperty
		if err := json.Unmarshal(ta.Details, &dp); err != nil {
			return nil, err
		}
		p = &dp
	case strings.ToLower(string(oam.SimpleProperty)):
		var sp oamgen.SimpleProperty
		if err := json.Unmarshal(ta.Details, &sp); err != nil {
			return nil, err
		}
		p = &sp
	case strings.ToLower(string(oam.SourceProperty)):
		var sp oamgen.SourceProperty
		if err := json.Unmarshal(ta.Details, &sp); err != nil {
			return nil, err
		}
		p = &sp
	case strings.ToLower(string(oam.VulnProperty)):
		var vp oamplat.VulnProperty
		if err := json.Unmarshal(ta.Details, &vp); err != nil {
			return nil, err
		}
		p = &vp
	default:
		return nil, fmt.Errorf("unknown property type: %s", ta.Tag.Namespace)
	}

	return p, nil
}

func (r *sqliteRepository) DeleteEntityTag(ctx context.Context, id string) error {
	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	tid, err := r.queries.RemoveEntityTag(ctx, mid)
	if err != nil {
		return err
	}

	_, err = r.queries.DeleteTagByID(ctx, tid, true)
	return err
}

func (r *sqliteRepository) CreateEdgeTag(ctx context.Context, edge *types.Edge, tag *types.EdgeTag) (*types.EdgeTag, error) {
	return r.CreateEdgeProperty(ctx, edge, tag.Property)
}

func (r *sqliteRepository) CreateEdgeProperty(ctx context.Context, edge *types.Edge, property oam.Property) (*types.EdgeTag, error) {
	_, err := r.stmts.UpsertTag(ctx, string(property.PropertyType()), property.Name(), property.Value(), "{}")
	if err != nil {
		return nil, err
	}

	eid, err := strconv.ParseInt(edge.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	details, err := property.JSON()
	if err != nil {
		return nil, err
	}

	mid, err := r.stmts.TagEdge(ctx, eid, string(property.PropertyType()), property.Name(), property.Value(), string(details))
	if err != nil {
		return nil, err
	}

	tags, err := r.queries.TagsForEdge(ctx, eid)
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
		CreatedAt: (*assignment).CreatedAt.In(time.UTC).Local(),
		LastSeen:  (*assignment).UpdatedAt.In(time.UTC).Local(),
		Property:  property,
		Edge:      edge,
	}, nil
}

func (r *sqliteRepository) FindEdgeTagById(ctx context.Context, id string) (*types.EdgeTag, error) {
	const q = `
SELECT m.id, m.edge_id, tg.tag_id, tg.namespace, tg.name, tg.value, tg.meta, m.details, tg.updated_at, m.created_at, m.updated_at
FROM edge_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.id = ?
ORDER BY m.updated_at DESC`
	st, err := r.queries.prepNamed(ctx, "q.tags.edgeTagById", q)
	if err != nil {
		return nil, err
	}

	rows, err := st.QueryContext(ctx, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	rows.Next()
	var eid int64
	var ta TagAssignment
	var created, updated, tupdated *string
	var v *string
	var meta, det *string
	if err := rows.Scan(
		&ta.ID, &eid, &ta.Tag.TagID, &ta.Tag.Namespace,
		&ta.Tag.Name, &v, &meta, &det, &created, &updated, &tupdated,
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

func (r *sqliteRepository) FindEdgeTags(ctx context.Context, edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {
	eid, err := strconv.ParseInt(edge.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	tags, err := r.queries.TagsForEdge(ctx, eid)
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

func (r *sqliteRepository) DeleteEdgeTag(ctx context.Context, id string) error {
	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	tid, err := r.queries.RemoveEdgeTag(ctx, mid)
	if err != nil {
		return err
	}

	_, err = r.queries.DeleteTagByID(ctx, tid, true)
	return err
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
SELECT m.id, tg.tag_id, tg.namespace, tg.name, tg.value, tg.meta, m.details, tg.updated_at, m.created_at, m.updated_at
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
	defer func() { _ = rows.Close() }()

	var out []TagAssignment
	for rows.Next() {
		var ta TagAssignment
		var created, updated, tupdated *string
		var v *string
		var meta, det *string
		if err := rows.Scan(
			&ta.ID, &ta.Tag.TagID, &ta.Tag.Namespace,
			&ta.Tag.Name, &v, &meta, &det, &tupdated, &created, &updated,
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
		ta.CreatedAt = parseTS(created)
		ta.UpdatedAt = parseTS(updated)
		ta.Tag.UpdatedAt = parseTS(tupdated)
		out = append(out, ta)
	}
	return out, rows.Err()
}

// TagsForEdge lists all tags assigned to an edge.
func (r *Queries) TagsForEdge(ctx context.Context, edgeID int64) ([]TagAssignment, error) {
	const q = `
SELECT m.id, tg.tag_id, tg.namespace, tg.name, tg.value, tg.meta, m.details, tg.updated_at, m.created_at, m.updated_at
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
	defer func() { _ = rows.Close() }()

	var out []TagAssignment
	for rows.Next() {
		var ta TagAssignment
		var created, updated, tupdated *string
		var v *string
		var meta, det *string
		if err := rows.Scan(
			&ta.ID, &ta.Tag.TagID, &ta.Tag.Namespace,
			&ta.Tag.Name, &v, &meta, &det, &created, &updated, &tupdated,
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
		ta.CreatedAt = parseTS(created)
		ta.UpdatedAt = parseTS(updated)
		ta.Tag.UpdatedAt = parseTS(tupdated)
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
	defer func() { _ = rows.Close() }()

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
func (r *Queries) RemoveEntityTag(ctx context.Context, mid int64) (int64, error) {
	tid, err := r.entityMIDToTID(ctx, mid)
	if err != nil {
		return 0, err
	}

	sb := strings.Builder{}
	args := []any{mid}
	sb.WriteString(`
DELETE FROM entity_tag_map
WHERE id = ? AND tag_id IN (
  SELECT tag_id FROM tags WHERE 1=1`)
	sb.WriteString(")")
	q := sb.String()
	_, err = r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}

	return tid, nil
}

func (r *Queries) entityMIDToTID(ctx context.Context, mid int64) (int64, error) {
	const q = `
SELECT tg.tag_id
FROM entity_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.id = ?
ORDER BY m.updated_at DESC`
	st, err := r.prepNamed(ctx, "q.tags.entityMIDToTID", q)
	if err != nil {
		return 0, err
	}
	rows, err := st.QueryContext(ctx, mid)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	rows.Next()
	var tid int64
	if err := rows.Scan(&tid); err != nil {
		return 0, err
	}
	return tid, nil
}

// RemoveEdgeTag deletes a specific tag mapping from an edge.
func (r *Queries) RemoveEdgeTag(ctx context.Context, mid int64) (int64, error) {
	tid, err := r.edgeMIDToTID(ctx, mid)
	if err != nil {
		return 0, err
	}

	sb := strings.Builder{}
	args := []any{mid}
	sb.WriteString(`
DELETE FROM edge_tag_map
WHERE id = ? AND tag_id IN (
  SELECT tag_id FROM tags WHERE 1=1`)
	sb.WriteString(")")
	q := sb.String()
	_, err = r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}

	return tid, nil
}

func (r *Queries) edgeMIDToTID(ctx context.Context, mid int64) (int64, error) {
	const q = `
SELECT tg.tag_id
FROM edge_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.id = ?
ORDER BY m.updated_at DESC`
	st, err := r.prepNamed(ctx, "q.tags.edgeMIDToTID", q)
	if err != nil {
		return 0, err
	}
	rows, err := st.QueryContext(ctx, mid)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	rows.Next()
	var tid int64
	if err := rows.Scan(&tid); err != nil {
		return 0, err
	}
	return tid, nil
}

// DeleteTagByID deletes a tag dictionary row.
// If onlyIfOrphaned is true, it deletes only when the tag is unused by any entity/edge mapping.
// Returns affected rows (0 if not deleted).
func (r *Queries) DeleteTagByID(ctx context.Context, tagID int64, onlyIfOrphaned bool) (int64, error) {
	if onlyIfOrphaned {
		const q = `
DELETE FROM tags
WHERE tag_id = ?
  AND NOT EXISTS (SELECT 1 FROM entity_tag_map WHERE tag_id = tags.tag_id)
  AND NOT EXISTS (SELECT 1 FROM edge_tag_map   WHERE tag_id = tags.tag_id)`
		res, err := r.db.ExecContext(ctx, q, tagID)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}

	// Unconditional delete (FK CASCADE should clean maps if configured; else do it manually)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM entity_tag_map WHERE tag_id = ?`, tagID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM edge_tag_map WHERE tag_id = ?`, tagID); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM tags WHERE tag_id = ?`, tagID)
	if err != nil {
		return 0, err
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		return 0, sql.ErrNoRows
	}
	return aff, tx.Commit()
}
