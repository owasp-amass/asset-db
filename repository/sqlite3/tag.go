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
	"strings"

	_ "github.com/mattn/go-sqlite3"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: :ttype_name, :property_name, :property_value, :content(JSON)
const upsertTagText = `
INSERT INTO tag(ttype_id, property_name, property_value, content)
VALUES ((SELECT id FROM tag_type_lu WHERE name = lower(:ttype_name) LIMIT 1), 
	:property_name, :property_value, coalesce(:content, '{}'))
ON CONFLICT(ttype_id, property_name, property_value) DO UPDATE SET
    content = CASE
        WHEN json_patch(tag.content, coalesce(excluded.content,'{}')) IS NOT tag.content
        THEN json_patch(tag.content, coalesce(excluded.content,'{}'))
        ELSE tag.content
    END,
    updated_at = CURRENT_TIMESTAMP`

// Params: :ttype_name, :property_name, :property_value
const selectTagIDByTagText = `
SELECT tag_id FROM tag 
JOIN tag_type_lu tt ON tt.id = tag.ttype_id
WHERE tt.name = lower(:ttype_name) AND tag.property_name = :property_name 
  AND coalesce(tag.property_value,'∅') = coalesce(:property_value,'∅')
LIMIT 1`

func (r *SqliteRepository) upsertTag(ctx context.Context, ttype, name, value, content string) (int64, error) {
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "tag.upsert",
		SQLText: upsertTagText,
		Args: []any{
			sql.Named("ttype_name", ttype),
			sql.Named("property_name", name),
			sql.Named("property_value", value),
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
		Name:    "tag.id_by_tag",
		SQLText: selectTagIDByTagText,
		Args: []any{
			sql.Named("ttype_name", ttype),
			sql.Named("property_name", name),
			sql.Named("property_value", value),
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

// deleteTagByID deletes a tag dictionary row.
// If onlyIfOrphaned is true, it deletes only when the tag is unused by any entity/edge mapping.
// Returns affected rows (0 if not deleted).
func (r *SqliteRepository) deleteTagByID(ctx context.Context, tagID int64, onlyIfOrphaned bool) error {
	if onlyIfOrphaned {
		const q = `
DELETE FROM tag 
WHERE tag_id = :tag_id
  AND NOT EXISTS (SELECT 1 FROM entity_tag_map WHERE tag_id = tag.tag_id)
  AND NOT EXISTS (SELECT 1 FROM edge_tag_map   WHERE tag_id = tag.tag_id)`

		done := make(chan error, 1)
		r.ww.Submit(&writeJob{
			Ctx:     ctx,
			Name:    "tag.delete_if_orphaned",
			SQLText: q,
			Args:    []any{sql.Named("tag_id", tagID)},
			Result:  done,
		})

		return <-done
	}

	// Unconditional delete (FK CASCADE should clean maps if configured; else do it manually)
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "tag.delete.entity_tag_mappings",
		SQLText: `DELETE FROM entity_tag_map WHERE tag_id = :tag_id`,
		Args:    []any{sql.Named("tag_id", tagID)},
		Result:  done,
	})
	err := <-done
	if err != nil {
		return err
	}

	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "tag.delete.edge_tag_mappings",
		SQLText: `DELETE FROM edge_tag_map WHERE tag_id = :tag_id`,
		Args:    []any{sql.Named("tag_id", tagID)},
		Result:  done,
	})
	err = <-done
	if err != nil {
		return err
	}

	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "tag.delete.tag_by_id",
		SQLText: `DELETE FROM tag WHERE tag_id = :tag_id`,
		Args:    []any{sql.Named("tag_id", tagID)},
		Result:  done,
	})

	return <-done
}

func extractOAMProperty(ttype string, content []byte) (oam.Property, error) {
	err := errors.New("failed to extract property from the JSON")

	if len(content) == 0 {
		return nil, err
	}

	var p oam.Property
	switch strings.ToLower(ttype) {
	case strings.ToLower(string(oam.DNSRecordProperty)):
		var dp oamdns.DNSRecordProperty
		if e := json.Unmarshal(content, &dp); e == nil {
			p = &dp
			err = nil
		}
	case strings.ToLower(string(oam.SimpleProperty)):
		var sp oamgen.SimpleProperty
		if e := json.Unmarshal(content, &sp); e == nil {
			p = &sp
			err = nil
		}
	case strings.ToLower(string(oam.SourceProperty)):
		var sp oamgen.SourceProperty
		if e := json.Unmarshal(content, &sp); e == nil {
			p = &sp
			err = nil
		}
	case strings.ToLower(string(oam.VulnProperty)):
		var vp oamplat.VulnProperty
		if e := json.Unmarshal(content, &vp); e == nil {
			p = &vp
			err = nil
		}
	default:
		return nil, fmt.Errorf("unknown property type: %s", ttype)
	}

	return p, err
}
