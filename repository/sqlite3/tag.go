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

// Params: :ttype_name, :property_name, :property_value, :content(JSON)
const upsertTagText = `
INSERT INTO tags(ttype_id, property_name, property_value, content)
VALUES ((SELECT id FROM tag_type_lu WHERE name=:ttype_name LIMIT 1), 
	:property_name, :property_value, coalesce(:content,'{}'))
ON CONFLICT(ttype_id, property_name, property_value) DO UPDATE SET
    content = CASE
        WHEN json_patch(tags.content, coalesce(excluded.content,'{}')) IS NOT tags.content
        THEN json_patch(tags.content, coalesce(excluded.content,'{}'))
        ELSE tags.content
    END,
    updated_at = CURRENT_TIMESTAMP;`

// Params: :ttype_name, :property_name, :property_value
const selectTagIDByTagText = `
SELECT tag_id FROM tags
WHERE ttype_id = (SELECT id FROM tag_type_lu WHERE name = :ttype_name LIMIT 1)
  AND property_name = :property_name
  AND coalesce(property_value,'∅') = coalesce(:property_value,'∅')
LIMIT 1;`

// Params: :entity_id, :tag_id
const tagEntityText = `
INSERT INTO entity_tag_map(entity_id, tag_id)
VALUES (:entity_id, :tag_id)
ON CONFLICT(entity_id, tag_id) DO UPDATE SET
    updated_at = CURRENT_TIMESTAMP;`

// Params: :entity_id, :tag_id
const selectEntityTagMapIDText = `
SELECT id FROM entity_tag_map
WHERE entity_id = :entity_id
  AND tag_id = :tag_id
LIMIT 1;`

// Params: :edge_id, :tag_id
const tagEdgeText = `
INSERT INTO edge_tag_map(edge_id, tag_id)
VALUES (:edge_id, :tag_id)
ON CONFLICT(edge_id, tag_id) DO UPDATE SET
    updated_at = CURRENT_TIMESTAMP;`

// Params: :edge_id, :tag_id
const selectEdgeTagMapIDText = `
SELECT id FROM edge_tag_map
WHERE edge_id = :edge_id
  AND tag_id = :tag_id
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
	ID        int64      `json:"id"`
	Tag       Tag        `json:"tag"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func (r *SqliteRepository) CreateEntityTag(ctx context.Context, entity *types.Entity, tag *types.EntityTag) (*types.EntityTag, error) {
	return r.CreateEntityProperty(ctx, entity, tag.Property)
}

func (r *SqliteRepository) CreateEntityProperty(ctx context.Context, entity *types.Entity, property oam.Property) (*types.EntityTag, error) {
	content, err := property.JSON()
	if err != nil {
		return nil, err
	}

	tid, err := r.upsertTag(ctx, string(property.PropertyType()), property.Name(), property.Value(), string(content))
	if err != nil {
		return nil, err
	}

	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	mid, err := r.tagEntity(ctx, eid, tid)
	if err != nil {
		return nil, err
	}

	tags, err := r.tagsForEntity(ctx, eid)
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
		CreatedAt: assignment.CreatedAt.In(time.UTC).Local(),
		LastSeen:  assignment.UpdatedAt.In(time.UTC).Local(),
		Property:  property,
		Entity:    entity,
	}, nil
}

func (r *SqliteRepository) FindEntityTagById(ctx context.Context, id string) (*types.EntityTag, error) {
	const q = `
SELECT m.id, m.entity_id, tg.tag_id, (SELECT name FROM tag_type_lu WHERE id = tg.ttype_id LIMIT 1), 
	tg.property_name, tg.property_value, tg.content, tg.updated_at, m.created_at, m.updated_at
FROM entity_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.id = ?
ORDER BY m.updated_at DESC;`
	st, err := r.queries.getOrPrepare(ctx, "tag.entity_tag_by_id", q)
	if err != nil {
		return nil, err
	}

	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	rows, err := st.QueryContext(ctx, mid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	rows.Next()
	var eid int64
	var ta TagAssignment
	var created, updated, tupdated *string
	var v *string
	var meta *string
	if err := rows.Scan(
		&ta.ID, &eid, &ta.Tag.TagID, &ta.Tag.Namespace,
		&ta.Tag.Name, &v, &meta, &tupdated, &created, &updated,
	); err != nil {
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

	return &types.EntityTag{
		ID:        strconv.FormatInt(ta.ID, 10),
		CreatedAt: ta.CreatedAt.In(time.UTC).Local(),
		LastSeen:  ta.UpdatedAt.In(time.UTC).Local(),
		Property:  prop,
		Entity:    &types.Entity{ID: strconv.FormatInt(eid, 10)},
	}, nil
}

func (r *SqliteRepository) FindEntityTags(ctx context.Context, entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	tags, err := r.tagsForEntity(ctx, eid)
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
		if err := json.Unmarshal(ta.Tag.Meta, &dp); err != nil {
			return nil, err
		}
		p = &dp
	case strings.ToLower(string(oam.SimpleProperty)):
		var sp oamgen.SimpleProperty
		if err := json.Unmarshal(ta.Tag.Meta, &sp); err != nil {
			return nil, err
		}
		p = &sp
	case strings.ToLower(string(oam.SourceProperty)):
		var sp oamgen.SourceProperty
		if err := json.Unmarshal(ta.Tag.Meta, &sp); err != nil {
			return nil, err
		}
		p = &sp
	case strings.ToLower(string(oam.VulnProperty)):
		var vp oamplat.VulnProperty
		if err := json.Unmarshal(ta.Tag.Meta, &vp); err != nil {
			return nil, err
		}
		p = &vp
	default:
		return nil, fmt.Errorf("unknown property type: %s", ta.Tag.Namespace)
	}

	return p, nil
}

func (r *SqliteRepository) DeleteEntityTag(ctx context.Context, id string) error {
	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	tid, err := r.removeEntityTag(ctx, mid)
	if err != nil {
		return err
	}

	_, err = r.deleteTagByID(ctx, tid, true)
	return err
}

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
	const q = `
SELECT m.id, m.edge_id, tg.tag_id, (SELECT name FROM tag_type_lu WHERE id = tg.ttype_id LIMIT 1), 
	tg.property_name, tg.property_value, tg.content, tg.updated_at, m.created_at, m.updated_at
FROM edge_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.id = ?
ORDER BY m.updated_at DESC;`
	st, err := r.queries.getOrPrepare(ctx, "tag.edge_tag_by_id", q)
	if err != nil {
		return nil, err
	}

	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	rows, err := st.QueryContext(ctx, mid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	rows.Next()
	var eid int64
	var ta TagAssignment
	var created, updated, tupdated *string
	var v *string
	var meta *string
	if err := rows.Scan(
		&ta.ID, &eid, &ta.Tag.TagID, &ta.Tag.Namespace,
		&ta.Tag.Name, &v, &meta, &tupdated, &created, &updated,
	); err != nil {
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

	_, err = r.deleteTagByID(ctx, tid, true)
	return err
}

func (r *SqliteRepository) upsertTag(ctx context.Context, ttype, name, value, content string) (int64, error) {
	const keySel = "tag.upsert"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, upsertTagText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("ttype_name", ttype),
		sql.Named("property_name", name),
		sql.Named("property_value", value),
		sql.Named("content", content),
	)

	const keySel2 = "tag.id_by_tag"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectTagIDByTagText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx,
		sql.Named("ttype_name", ttype),
		sql.Named("property_name", name),
		sql.Named("property_value", value)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) tagEntity(ctx context.Context, entityID, tagID int64) (int64, error) {
	const keySel = "tag.upsert_entity_tag_mapping"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, tagEntityText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("entity_id", entityID),
		sql.Named("tag_id", tagID),
	)

	const keySel2 = "tag.entity_tag_mapping_id_by_ids"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEntityTagMapIDText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx,
		sql.Named("entity_id", entityID),
		sql.Named("tag_id", tagID)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *SqliteRepository) tagEdge(ctx context.Context, edgeID, tagID int64) (int64, error) {
	const keySel = "tag.upsert_edge_tag_mapping"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, tagEdgeText)
	if err != nil {
		return 0, err
	}

	_ = stmt.QueryRowContext(ctx,
		sql.Named("edge_id", edgeID),
		sql.Named("tag_id", tagID),
	)

	const keySel2 = "tag.edge_tag_mapping_id_by_ids"
	stmt2, err := r.queries.getOrPrepare(ctx, keySel2, selectEdgeTagMapIDText)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt2.QueryRowContext(ctx,
		sql.Named("edge_id", edgeID),
		sql.Named("tag_id", tagID)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// tagsForEntity lists all tag assignments for an entity (namespaced).
func (r *SqliteRepository) tagsForEntity(ctx context.Context, entityID int64) ([]TagAssignment, error) {
	const q = `
SELECT m.id, tg.tag_id, (SELECT name FROM tag_type_lu WHERE id = tg.ttype_id LIMIT 1), 
	tg.property_name, tg.property_value, tg.content, tg.updated_at, m.created_at, m.updated_at
FROM entity_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.entity_id = ?
ORDER BY m.updated_at DESC;`
	st, err := r.queries.getOrPrepare(ctx, "tag.for_entity", q)
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
		var meta *string
		if err := rows.Scan(
			&ta.ID, &ta.Tag.TagID, &ta.Tag.Namespace,
			&ta.Tag.Name, &v, &meta, &tupdated, &created, &updated,
		); err != nil {
			return nil, err
		}
		ta.Tag.Value = v
		if meta != nil && strings.TrimSpace(*meta) != "" {
			ta.Tag.Meta = json.RawMessage(*meta)
		}

		ta.CreatedAt = parseTS(created)
		ta.UpdatedAt = parseTS(updated)
		ta.Tag.UpdatedAt = parseTS(tupdated)
		out = append(out, ta)
	}
	return out, rows.Err()
}

// tagsForEdge lists all tags assigned to an edge.
func (r *SqliteRepository) tagsForEdge(ctx context.Context, edgeID int64) ([]TagAssignment, error) {
	const q = `
SELECT m.id, tg.tag_id, (SELECT name FROM tag_type_lu WHERE id = tg.ttype_id LIMIT 1), 
	tg.property_name, tg.property_value, tg.content, tg.updated_at, m.created_at, m.updated_at
FROM edge_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.edge_id = ?
ORDER BY m.updated_at DESC;`
	st, err := r.queries.getOrPrepare(ctx, "tag.for_edge", q)
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
		var meta *string
		if err := rows.Scan(
			&ta.ID, &ta.Tag.TagID, &ta.Tag.Namespace,
			&ta.Tag.Name, &v, &meta, &tupdated, &created, &updated,
		); err != nil {
			return nil, err
		}
		ta.Tag.Value = v
		if meta != nil && strings.TrimSpace(*meta) != "" {
			ta.Tag.Meta = json.RawMessage(*meta)
		}
		ta.CreatedAt = parseTS(created)
		ta.UpdatedAt = parseTS(updated)
		ta.Tag.UpdatedAt = parseTS(tupdated)
		out = append(out, ta)
	}
	return out, rows.Err()
}

// removeEntityTag deletes a specific tag mapping from an entity.
func (r *SqliteRepository) removeEntityTag(ctx context.Context, mid int64) (int64, error) {
	tid, err := r.entityMIDToTID(ctx, mid)
	if err != nil {
		return 0, err
	}

	const q = `DELETE FROM entity_tag_map WHERE id = ?;`
	stmt, err := r.queries.getOrPrepare(ctx, "tag.remove_entity_tag", q)
	if err != nil {
		return 0, err
	}

	args := []any{mid}
	_, err = stmt.ExecContext(ctx, args...)
	if err != nil {
		return 0, err
	}

	return tid, nil
}

func (r *SqliteRepository) entityMIDToTID(ctx context.Context, mid int64) (int64, error) {
	const q = `
SELECT tg.tag_id
FROM entity_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.id = ?
ORDER BY m.updated_at DESC;`
	st, err := r.queries.getOrPrepare(ctx, "tag.entity_mid_to_tid", q)
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

// removeEdgeTag deletes a specific tag mapping from an edge.
func (r *SqliteRepository) removeEdgeTag(ctx context.Context, mid int64) (int64, error) {
	tid, err := r.edgeMIDToTID(ctx, mid)
	if err != nil {
		return 0, err
	}

	const q = `DELETE FROM edge_tag_map WHERE id = ?;`
	stmt, err := r.queries.getOrPrepare(ctx, "tag.remove_edge_tag", q)
	if err != nil {
		return 0, err
	}

	args := []any{mid}
	_, err = stmt.ExecContext(ctx, args...)
	if err != nil {
		return 0, err
	}

	return tid, nil
}

func (r *SqliteRepository) edgeMIDToTID(ctx context.Context, mid int64) (int64, error) {
	const q = `
SELECT tg.tag_id
FROM edge_tag_map m
JOIN tags tg ON tg.tag_id = m.tag_id
WHERE m.id = ?
ORDER BY m.updated_at DESC;`
	st, err := r.queries.getOrPrepare(ctx, "tag.edge_mid_to_tid", q)
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

// deleteTagByID deletes a tag dictionary row.
// If onlyIfOrphaned is true, it deletes only when the tag is unused by any entity/edge mapping.
// Returns affected rows (0 if not deleted).
func (r *SqliteRepository) deleteTagByID(ctx context.Context, tagID int64, onlyIfOrphaned bool) (int64, error) {
	if onlyIfOrphaned {
		const q = `
DELETE FROM tags
WHERE tag_id = ?
  AND NOT EXISTS (SELECT 1 FROM entity_tag_map WHERE tag_id = tags.tag_id)
  AND NOT EXISTS (SELECT 1 FROM edge_tag_map   WHERE tag_id = tags.tag_id);`
		res, err := r.DB.ExecContext(ctx, q, tagID)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}

	// Unconditional delete (FK CASCADE should clean maps if configured; else do it manually)
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM entity_tag_map WHERE tag_id = ?;`, tagID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM edge_tag_map WHERE tag_id = ?;`, tagID); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM tags WHERE tag_id = ?;`, tagID)
	if err != nil {
		return 0, err
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		return 0, sql.ErrNoRows
	}
	return aff, tx.Commit()
}
