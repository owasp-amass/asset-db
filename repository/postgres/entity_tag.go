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

// Params: @entity_id, @ttype, @name, @value, @content(JSON)
const tagEntityText = `SELECT public.entity_tag_upsert(@entity_id::bigint, @ttype::text, @name::text, @value::text, @content::jsonb);`

// Param: @tag_id
const selectEntityTagByIDText = `SELECT t.tag_id, t.entity_id, t.created_at, t.updated_at, t.ttype_name, t.content 
FROM public.get_entity_tag_by_id(@tag_id::bigint) as t;`

// Params: @entity_id, @since, @names
const entityGetTagsText = `SELECT t.tag_id, t.created_at, t.updated_at, t.ttype_name, t.content 
FROM public.entity_get_tags(@entity_id::bigint, @since::timestamp, @names::text[]) as t;`

func (r *PostgresRepository) CreateEntityTag(ctx context.Context, entity *dbt.Entity, tag *dbt.EntityTag) (*dbt.EntityTag, error) {
	return r.CreateEntityProperty(ctx, entity, tag.Property)
}

func (r *PostgresRepository) CreateEntityProperty(ctx context.Context, entity *dbt.Entity, property oam.Property) (*dbt.EntityTag, error) {
	content, err := property.JSON()
	if err != nil {
		return nil, err
	}

	eid, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	var tid int64
	j := NewRowJob(ctx, tagEntityText, pgx.NamedArgs{
		"entity_id": eid,
		"ttype":     string(property.PropertyType()),
		"name":      property.Name(),
		"value":     property.Value(),
		"content":   string(content),
	}, func(row pgx.Row) error {
		return row.Scan(&tid)
	})
	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	idstr := strconv.FormatInt(tid, 10)
	return r.FindEntityTagById(ctx, idstr)
}

func (r *PostgresRepository) FindEntityTagById(ctx context.Context, id string) (*dbt.EntityTag, error) {
	tid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	var eid int64
	var c, u time.Time
	var ttype, content string
	j := NewRowJob(ctx, selectEntityTagByIDText, pgx.NamedArgs{
		"tag_id": tid,
	}, func(row pgx.Row) error {
		return row.Scan(&tid, &eid, &c, &u, &ttype, &content)
	})

	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	tag := &dbt.EntityTag{
		ID:        id,
		CreatedAt: c.In(time.UTC).Local(),
		LastSeen:  u.In(time.UTC).Local(),
		Entity:    &dbt.Entity{ID: strconv.FormatInt(eid, 10)},
	}

	prop, err := extractOAMProperty(ttype, json.RawMessage(content))
	if err != nil {
		return nil, err
	}
	tag.Property = prop

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
	tid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	_, err = r.removeEntityTag(ctx, tid)
	if err != nil {
		return err
	}
	return nil
}

// tagsForEntity lists all tag assignments for an entity (namespaced).
func (r *PostgresRepository) tagsForEntity(ctx context.Context, eid int64, since time.Time, names ...string) ([]*dbt.EntityTag, error) {
	if !since.IsZero() {
		since = since.UTC()
	}
	ts := zeronull.Timestamp(since)

	if len(names) == 0 {
		names = nil
	}

	var out []*dbt.EntityTag
	j := NewRowsJob(ctx, entityGetTagsText, pgx.NamedArgs{
		"entity_id": eid,
		"since":     ts,
		"names":     names,
	}, func(rows pgx.Rows) error {
		for rows.Next() {
			var tid int64
			var c, u time.Time
			var ttype, content string

			if err := rows.Scan(&tid, &c, &u, &ttype, &content); err != nil {
				continue
			}

			tag := &dbt.EntityTag{
				ID:        strconv.FormatInt(tid, 10),
				CreatedAt: c.In(time.UTC).Local(),
				LastSeen:  u.In(time.UTC).Local(),
				Entity:    &dbt.Entity{ID: strconv.FormatInt(eid, 10)},
			}

			prop, err := extractOAMProperty(ttype, json.RawMessage(content))
			if err != nil {
				continue
			}
			tag.Property = prop

			out = append(out, tag)
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

// removeEntityTag deletes a specific tag from an entity.
func (r *PostgresRepository) removeEntityTag(ctx context.Context, tid int64) (int64, error) {
	j := NewExecJob(ctx, `DELETE FROM public.entity_tag WHERE tag_id = @tag_id`, pgx.NamedArgs{
		"tag_id": tid,
	}, func(tag pgconn.CommandTag) error {
		if tag.RowsAffected() == 0 {
			return errors.New("entity tag not found")
		}
		return nil
	})

	r.pool.Submit(j)
	return tid, j.Wait()
}
