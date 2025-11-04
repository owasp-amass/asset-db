// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Params: :entity_id, :tag_id
const tagEntityText = `
INSERT INTO entity_tag_map(entity_id, tag_id)
VALUES (:entity_id, :tag_id)
ON CONFLICT(entity_id, tag_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP`

// Params: :entity_id, :tag_id
const selectEntityTagMapIDText = `
SELECT id FROM entity_tag_map
WHERE entity_id = :entity_id AND tag_id = :tag_id 
LIMIT 1`

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
	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	const q = `
SELECT m.id, m.entity_id, tg.tag_id, (SELECT name FROM tag_type_lu WHERE id = tg.ttype_id LIMIT 1), 
	tg.property_name, tg.property_value, tg.content, tg.updated_at, m.created_at, m.updated_at
FROM entity_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
WHERE m.id = :map_id
ORDER BY m.updated_at DESC
LIMIT 1`

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "entity.tag.by_id",
		SQLText: q,
		Args:    []any{sql.Named("map_id", mid)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var eid int64
	var ta TagAssignment
	var v, meta, c, u, tu string
	if err := result.Row.Scan(&ta.ID, &eid, &ta.Tag.TagID,
		&ta.Tag.Namespace, &ta.Tag.Name, &v, &meta, &tu, &c, &u); err != nil {
		return nil, err
	}

	ta.Tag.Value = &v
	if meta != "" && strings.TrimSpace(meta) != "" {
		ta.Tag.Meta = json.RawMessage(meta)
	}

	var created, updated time.Time
	if c, err := parseTimestamp(c); err != nil {
		return nil, err
	} else {
		created = c.In(time.UTC).Local()
	}
	if u, err := parseTimestamp(u); err != nil {
		return nil, err
	} else {
		updated = u.In(time.UTC).Local()
	}

	prop, err := convertSQLitePropertyToOAMProperty(&ta)
	if err != nil {
		return nil, err
	}

	return &types.EntityTag{
		ID:        strconv.FormatInt(ta.ID, 10),
		CreatedAt: created,
		LastSeen:  updated,
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

func (r *SqliteRepository) DeleteEntityTag(ctx context.Context, id string) error {
	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	tid, err := r.removeEntityTag(ctx, mid)
	if err != nil {
		return err
	}

	return r.deleteTagByID(ctx, tid, true)
}

func (r *SqliteRepository) tagEntity(ctx context.Context, entityID, tagID int64) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "entity.tag.upsert_entity_tag_mapping",
		SQLText: tagEntityText,
		Args: []any{
			sql.Named("entity_id", entityID),
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
		Name:    "entity.tag.entity_tag_mapping_id_by_ids",
		SQLText: selectEntityTagMapIDText,
		Args: []any{
			sql.Named("entity_id", entityID),
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

// tagsForEntity lists all tag assignments for an entity (namespaced).
func (r *SqliteRepository) tagsForEntity(ctx context.Context, entityID int64) ([]TagAssignment, error) {
	const q = `
SELECT m.id, tg.tag_id, (SELECT name FROM tag_type_lu WHERE id = tg.ttype_id LIMIT 1), 
	tg.property_name, tg.property_value, tg.content, tg.updated_at, m.created_at, m.updated_at
FROM entity_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
WHERE m.entity_id = :entity_id
ORDER BY m.updated_at DESC`

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{
		Ctx:     ctx,
		Name:    "entity.tags_for_entity",
		SQLText: q,
		Args:    []any{sql.Named("entity_id", entityID)},
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
		var v, meta, c, u, tu string

		if err := result.Rows.Scan(&ta.ID, &ta.Tag.TagID,
			&ta.Tag.Namespace, &ta.Tag.Name, &v, &meta, &tu, &c, &u); err != nil {
			return nil, err
		}

		ta.Tag.Value = &v
		if meta != "" && strings.TrimSpace(meta) != "" {
			ta.Tag.Meta = json.RawMessage(meta)
		}

		if c, err := parseTimestamp(c); err != nil {
			return nil, err
		} else {
			created := c.In(time.UTC).Local()
			ta.CreatedAt = &created
		}
		if u, err := parseTimestamp(u); err != nil {
			return nil, err
		} else {
			updated := u.In(time.UTC).Local()
			ta.UpdatedAt = &updated
		}
		if tu, err := parseTimestamp(tu); err != nil {
			return nil, err
		} else {
			tupdated := tu.In(time.UTC).Local()
			ta.Tag.UpdatedAt = &tupdated
		}

		out = append(out, ta)
	}

	return out, result.Rows.Err()
}

// removeEntityTag deletes a specific tag mapping from an entity.
func (r *SqliteRepository) removeEntityTag(ctx context.Context, mid int64) (int64, error) {
	tid, err := r.entityMIDToTID(ctx, mid)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "entity.tag.remove_entity_tag",
		SQLText: `DELETE FROM entity_tag_map WHERE id = :map_id`,
		Args:    []any{sql.Named("map_id", mid)},
		Result:  done,
	})

	return tid, <-done
}

func (r *SqliteRepository) entityMIDToTID(ctx context.Context, mid int64) (int64, error) {
	const q = `
SELECT tg.tag_id
FROM entity_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
WHERE m.id = :map_id
ORDER BY m.updated_at DESC 
LIMIT 1;`

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "entity.tag.mid_to_tid",
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
