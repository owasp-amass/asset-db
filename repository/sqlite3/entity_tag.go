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
	"strings"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	_ "modernc.org/sqlite"
)

// Params: :entity_id, :ttype_name, :property_name, :property_value, :content(JSON)
const tagEntityText = `
INSERT INTO entity_tag(entity_id, ttype_id, property_name, property_value, content)
VALUES (:entity_id, (SELECT id FROM tag_type_lu WHERE name = lower(:ttype_name) LIMIT 1), 
	:property_name, :property_value, coalesce(:content, '{}'))
ON CONFLICT(entity_id, ttype_id, property_name, property_value) DO UPDATE SET
    content = CASE
        WHEN json_patch(entity_tag.content, coalesce(excluded.content,'{}')) IS NOT entity_tag.content
          THEN json_patch(entity_tag.content, coalesce(excluded.content,'{}'))
        ELSE entity_tag.content
    END,
    updated_at = CURRENT_TIMESTAMP`

// Params: :entity_id, :ttype_name, :property_name, :property_value
const selectEntityTagIDText = `
SELECT tag_id FROM entity_tag 
JOIN tag_type_lu tt ON tt.id = entity_tag.ttype_id
WHERE entity_tag.entity_id = :entity_id AND tt.name = lower(:ttype_name) 
  AND entity_tag.property_name = :property_name 
  AND coalesce(entity_tag.property_value,'∅') = coalesce(:property_value,'∅')
LIMIT 1`

// CreateEntityTag implements the Repository interface.
func (r *SqliteRepository) CreateEntityTag(ctx context.Context, entity *dbt.Entity, tag *dbt.EntityTag) (*dbt.EntityTag, error) {
	return r.CreateEntityProperty(ctx, entity, tag.Property)
}

// CreateEntityProperty implements the Repository interface.
func (r *SqliteRepository) CreateEntityProperty(ctx context.Context, entity *dbt.Entity, property oam.Property) (*dbt.EntityTag, error) {
	content, err := property.JSON()
	if err != nil {
		return nil, err
	}

	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	tid, err := r.tagEntity(ctx, eid, property, string(content))
	if err != nil {
		return nil, err
	}

	idstr := strconv.FormatInt(tid, 10)
	return r.FindEntityTagById(ctx, idstr)
}

// FindEntityTagById implements the Repository interface.
func (r *SqliteRepository) FindEntityTagById(ctx context.Context, id string) (*dbt.EntityTag, error) {
	tid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	const q = `
SELECT et.tag_id, et.entity_id, et.created_at, et.updated_at, tt.name, et.content
FROM entity_tag et
JOIN tag_type_lu tt ON tt.id = et.ttype_id
WHERE et.tag_id = :tag_id
LIMIT 1`

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "entity.tag.by_id",
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

	tag := &dbt.EntityTag{
		ID:     id,
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

// FindEntityTags implements the Repository interface.
func (r *SqliteRepository) FindEntityTags(ctx context.Context, entity *dbt.Entity, since time.Time, names ...string) ([]*dbt.EntityTag, error) {
	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	return r.tagsForEntity(ctx, eid, since, names...)
}

// DeleteEntityTag implements the Repository interface.
func (r *SqliteRepository) DeleteEntityTag(ctx context.Context, id string) error {
	tid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "entity.tag.delete",
		SQLText: `DELETE FROM entity_tag WHERE tag_id = :tag_id`,
		Args:    []any{sql.Named("tag_id", tid)},
		Result:  done,
	})
	return <-done
}

func (r *SqliteRepository) tagEntity(ctx context.Context, entityID int64, property oam.Property, content string) (int64, error) {
	done := make(chan error, 1)
	ttype := string(property.PropertyType())

	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "entity.tag.upsert",
		SQLText: tagEntityText,
		Args: []any{
			sql.Named("entity_id", entityID),
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
		Name:    "entity.tag.id_by_valuess",
		SQLText: selectEntityTagIDText,
		Args: []any{
			sql.Named("entity_id", entityID),
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

// tagsForEntity lists all tag assignments for an entity (namespaced).
func (r *SqliteRepository) tagsForEntity(ctx context.Context, eid int64, since time.Time, names ...string) ([]*dbt.EntityTag, error) {
	key := "entity.tags_for_entity"
	args := []any{sql.Named("entity_id", eid)}
	q := `
SELECT et.tag_id, et.created_at, et.updated_at, tt.name, et.content
FROM entity_tag et
JOIN tag_type_lu tt ON tt.id = et.ttype_id
WHERE et.entity_id = :entity_id`

	if !since.IsZero() {
		key += ".since"
		q += " AND et.updated_at >= :since"
		args = append(args, sql.Named("since", since.UTC()))
	}

	if len(names) > 0 {
		key += "." + strings.Join(names, ".")
		list := `('` + strings.Join(names, `', '`) + `')`
		q += " AND et.property_name IN " + list
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

	var out []*dbt.EntityTag
	for result.Rows.Next() {
		var tid int64
		var ttype, content, c, u string

		if err := result.Rows.Scan(&tid, &c, &u, &ttype, &content); err != nil {
			return nil, err
		}

		tag := &dbt.EntityTag{
			ID:     strconv.FormatInt(tid, 10),
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
