// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
const tagEntityText = `SELECT t.out_tag_id, t.out_map_id 
FROM public.entity_tag_map_upsert(@entity_id::bigint, @ttype::text, @name::text, @value::text, @content::jsonb) as t;`

// Param: @map_id
const selectEntityTagMapByIDText = `SELECT t.tag_id, t.entity_id, t.created_at, t.updated_at, t.ttype_name, t.content 
FROM public.get_entity_tag_map_by_id(@map_id::bigint) as t;`

// Params: @entity_id, @since, @names
const entityGetTagsText = `SELECT t.tag_id, t.map_id, t.created_at, t.updated_at, t.ttype_name, t.content 
FROM public.entity_get_tags(@entity_id::bigint, @since::timestamp, @names::text[]) as t;`

// Param: @map_id
const selectTagIDByEntityTagMapIDText = `SELECT public.entity_tag_map_get_tag_id(@map_id::bigint);`

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

	var tid, mid int64
	j := NewRowJob(ctx, tagEntityText, pgx.NamedArgs{
		"entity_id": eid,
		"ttype":     string(property.PropertyType()),
		"name":      property.Name(),
		"value":     property.Value(),
		"content":   string(content),
	}, func(row pgx.Row) error {
		return row.Scan(&tid, &mid)
	})
	r.pool.Submit(j)
	if err := j.Wait(); err != nil {
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

	var eid, tid int64
	var c, u time.Time
	var ttype, content string
	j := NewRowJob(ctx, selectEntityTagMapByIDText, pgx.NamedArgs{
		"map_id": mid,
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
			var tid, mid int64
			var c, u time.Time
			var ttype, content string

			if err := rows.Scan(&tid, &mid, &c, &u, &ttype, &content); err != nil {
				continue
			}

			tag := &dbt.EntityTag{
				ID:        strconv.FormatInt(mid, 10),
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

// removeEntityTag deletes a specific tag mapping from an entity.
func (r *PostgresRepository) removeEntityTag(ctx context.Context, mid int64) (int64, error) {
	tid, err := r.entityMIDToTID(ctx, mid)
	if err != nil {
		return 0, err
	}

	j := NewExecJob(ctx, `DELETE FROM public.entity_tag_map WHERE map_id = @map_id`, pgx.NamedArgs{
		"map_id": mid,
	}, func(tag pgconn.CommandTag) error {
		if tag.RowsAffected() == 0 {
			return errors.New("entity tag map not found")
		}
		return nil
	})

	r.pool.Submit(j)
	return tid, j.Wait()
}

func (r *PostgresRepository) entityMIDToTID(ctx context.Context, mid int64) (int64, error) {
	if mid == 0 {
		return 0, errors.New("invalid entity tag map ID")
	}

	var tid int64
	j := NewRowJob(ctx, selectTagIDByEntityTagMapIDText, pgx.NamedArgs{
		"map_id": mid,
	}, func(row pgx.Row) error {
		return row.Scan(&tid)
	})

	r.pool.Submit(j)
	return tid, j.Wait()
}
