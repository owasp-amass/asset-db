// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Params: :entity_id, :tag_id
const tagEntityText = `
INSERT INTO entity_tag_map(entity_id, tag_id)
VALUES (:entity_id, :tag_id)
ON CONFLICT(entity_id, tag_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP`

// Params: :entity_id, :tag_id
const selectEntityTagMapIDText = `
SELECT map_id FROM entity_tag_map
WHERE entity_id = :entity_id AND tag_id = :tag_id 
LIMIT 1`

func (r *PostgresRepository) CreateEntityTag(ctx context.Context, entity *dbt.Entity, tag *dbt.EntityTag) (*dbt.EntityTag, error) {
	return r.CreateEntityProperty(ctx, entity, tag.Property)
}

func (r *PostgresRepository) CreateEntityProperty(ctx context.Context, entity *dbt.Entity, property oam.Property) (*dbt.EntityTag, error) {
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

	idstr := strconv.FormatInt(mid, 10)
	return r.FindEntityTagById(ctx, idstr)
}

func (r *PostgresRepository) FindEntityTagById(ctx context.Context, id string) (*dbt.EntityTag, error) {
	mid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	const q = `
SELECT m.map_id, m.entity_id, m.created_at, m.updated_at, tt.name, tg.content
FROM entity_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
JOIN tag_type_lu tt ON tt.id = tg.ttype_id
WHERE m.map_id = :map_id
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

	var eid, row_id int64
	var ttype, content, c, u string
	if err := result.Row.Scan(&row_id, &eid, &c, &u, &ttype, &content); err != nil {
		return nil, err
	}

	tag := &dbt.EntityTag{
		ID:     strconv.FormatInt(row_id, 10),
		Entity: &dbt.Entity{ID: strconv.FormatInt(eid, 10)},
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

func (r *PostgresRepository) FindEntityTags(ctx context.Context, entity *dbt.Entity, since time.Time, names ...string) ([]*dbt.EntityTag, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	return r.tagsForEntity(ctx, eid, since, names...)
}

func (r *PostgresRepository) DeleteEntityTag(ctx context.Context, id string) error {
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

func (r *PostgresRepository) tagEntity(ctx context.Context, entityID, tagID int64) (int64, error) {
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
func (r *PostgresRepository) tagsForEntity(ctx context.Context, eid int64, since time.Time, names ...string) ([]*dbt.EntityTag, error) {
	key := "entity.tags_for_entity"
	args := []any{sql.Named("entity_id", eid)}
	q := `
SELECT m.map_id, m.created_at, m.updated_at, tt.name, tg.content
FROM entity_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
JOIN tag_type_lu tt ON tt.id = tg.ttype_id
WHERE m.entity_id = :entity_id`

	if !since.IsZero() {
		key += ".since"
		q += " AND m.updated_at >= :since"
		args = append(args, sql.Named("since", since.UTC()))
	}

	if len(names) > 0 {
		key += "." + strings.Join(names, ".")
		list := `('` + strings.Join(names, `', '`) + `')`
		q += " AND tg.property_name IN " + list
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

	var out []*dbt.EntityTag
	for result.Rows.Next() {
		var row_id int64
		var ttype, content, c, u string

		if err := result.Rows.Scan(&row_id, &c, &u, &ttype, &content); err != nil {
			return nil, err
		}

		tag := &dbt.EntityTag{
			ID:     strconv.FormatInt(row_id, 10),
			Entity: &dbt.Entity{ID: strconv.FormatInt(eid, 10)},
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
		return nil, errors.New("no tags found for entity")
	}
	return out, nil
}

// removeEntityTag deletes a specific tag mapping from an entity.
func (r *PostgresRepository) removeEntityTag(ctx context.Context, mid int64) (int64, error) {
	tid, err := r.entityMIDToTID(ctx, mid)
	if err != nil {
		return 0, err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "entity.tag.remove_entity_tag",
		SQLText: `DELETE FROM entity_tag_map WHERE map_id = :map_id`,
		Args:    []any{sql.Named("map_id", mid)},
		Result:  done,
	})

	return tid, <-done
}

func (r *PostgresRepository) entityMIDToTID(ctx context.Context, mid int64) (int64, error) {
	const q = `
SELECT tg.tag_id
FROM entity_tag_map m
JOIN tag tg ON tg.tag_id = m.tag_id
WHERE m.map_id = :map_id
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
