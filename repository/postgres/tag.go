// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Params: @ttype, @name, @value, @content(JSON)
const upsertTagText = `SELECT public.tag_upsert(@ttype::text, @name::text, @value::text, @content::jsonb);`

func (r *PostgresRepository) upsertTag(ctx context.Context, ttype, name, value, content string) (int64, error) {
	if ttype == "" {
		return 0, fmt.Errorf("tag type cannot be empty")
	}
	if name == "" || value == "" {
		return 0, fmt.Errorf("tag name and value cannot be empty")
	}

	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "tag.upsert",
		SQLText: upsertTagText,
		Args: pgx.NamedArgs{
			"ttype":   ttype,
			"name":    name,
			"value":   value,
			"content": string(content),
		},
		Result: ch,
	})

	result := <-ch
	if result.Err != nil {
		return 0, result.Err
	}

	var id int64
	err := result.Row.Scan(&id)
	return id, err
}

// deleteTagByID deletes a tag dictionary row.
// If onlyIfOrphaned is true, it deletes only when the tag is unused by any entity/edge mapping.
// Returns affected rows (0 if not deleted).
func (r *PostgresRepository) deleteTagByID(ctx context.Context, tagID int64, onlyIfOrphaned bool) error {
	if onlyIfOrphaned {
		const q = `
DELETE FROM public.tag 
WHERE tag_id = @tag_id
  AND NOT EXISTS (SELECT 1 FROM public.entity_tag_map WHERE tag_id = tag.tag_id)
  AND NOT EXISTS (SELECT 1 FROM public.edge_tag_map   WHERE tag_id = tag.tag_id)`

		done := make(chan error, 1)
		r.wpool.Submit(&execJob{
			Ctx:     ctx,
			Name:    "tag.delete_if_orphaned",
			SQLText: q,
			Args:    pgx.NamedArgs{"tag_id": tagID},
			Result:  done,
		})

		return <-done
	}

	// Unconditional delete (FK CASCADE should clean maps if configured; else do it manually)
	done := make(chan error, 1)
	r.wpool.Submit(&execJob{
		Ctx:     ctx,
		Name:    "tag.delete.entity_tag_mappings",
		SQLText: `DELETE FROM public.entity_tag_map WHERE tag_id = @tag_id`,
		Args:    pgx.NamedArgs{"tag_id": tagID},
		Result:  done,
	})
	err := <-done
	if err != nil {
		return err
	}

	r.wpool.Submit(&execJob{
		Ctx:     ctx,
		Name:    "tag.delete.edge_tag_mappings",
		SQLText: `DELETE FROM public.edge_tag_map WHERE tag_id = @tag_id`,
		Args:    pgx.NamedArgs{"tag_id": tagID},
		Result:  done,
	})
	err = <-done
	if err != nil {
		return err
	}

	r.wpool.Submit(&execJob{
		Ctx:     ctx,
		Name:    "tag.delete.tag_by_id",
		SQLText: `DELETE FROM public.tag WHERE tag_id = @tag_id`,
		Args:    pgx.NamedArgs{"tag_id": tagID},
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
