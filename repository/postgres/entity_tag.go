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
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Params: @entity_id, @ttype, @name, @value, @content(JSON)
const tagEntityText = `SELECT public.entity_tag_map_upsert(@entity_id::bigint, @ttype::text, @name::text, @value::text, @content::jsonb);`

// Param: @map_id
const selectEntityTagMapByIDText = `SELECT public.get_entity_tag_map_by_id(@map_id::bigint);`

// Params: @entity_id, @since, @names
const entityGetTagsText = `SELECT public.entity_get_tags(@entity_id::bigint, @since::timestamp, @names::text[]);`

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

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "entity.tag.upsert",
		SQLText: tagEntityText,
		Args: pgx.NamedArgs{
			"entity_id": eid,
			"ttype":     string(property.PropertyType()),
			"name":      property.Name(),
			"value":     property.Value(),
			"content":   string(content),
		},
		Result: ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var tid, mid int64
	if err := result.Row.Scan(&tid, &mid); err != nil {
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

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "entity.tag.by_id",
		SQLText: selectEntityTagMapByIDText,
		Args:    pgx.NamedArgs{"map_id": mid},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var eid, tid int64
	var c, u time.Time
	var ttype, content string
	if err := result.Row.Scan(&tid, &eid, &c, &u, &ttype, &content); err != nil {
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

	ch := make(chan *rowsResult, 1)
	r.wpool.Submit(&rowsJob{
		Ctx:     ctx,
		Name:    "entity.tags_for_entity",
		SQLText: entityGetTagsText,
		Args: pgx.NamedArgs{
			"entity_id": eid,
			"since":     ts,
			"names":     names,
		},
		Result: ch,
	})

	result := <-ch
	if result.Rows != nil {
		defer func() { _ = result.Rows.Close() }()
	}
	if result.Err != nil {
		return nil, result.Err
	}

	var out []*dbt.EntityTag
	for result.Rows.Next() {
		var tid, mid int64
		var c, u time.Time
		var ttype, content string

		if err := result.Rows.Scan(&tid, &mid, &c, &u, &ttype, &content); err != nil {
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
	r.wpool.Submit(&execJob{
		Ctx:     ctx,
		Name:    "entity.tag.remove_entity_tag",
		SQLText: `DELETE FROM public.entity_tag_map WHERE map_id = @map_id`,
		Args:    pgx.NamedArgs{"map_id": mid},
		Result:  done,
	})

	return tid, <-done
}

func (r *PostgresRepository) entityMIDToTID(ctx context.Context, mid int64) (int64, error) {
	if mid == 0 {
		return 0, errors.New("invalid entity tag map ID")
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "entity.tag.mid_to_tid",
		SQLText: selectTagIDByEntityTagMapIDText,
		Args:    pgx.NamedArgs{"map_id": mid},
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
