// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// countedDelete makes a DELETE statement also add one to the deletion
// count when it removes a row, in the same statement. The statement affects
// no row when the DELETE removed none.
func countedDelete(del string) string {
	return `WITH gone AS (` + del + ` RETURNING 1)
UPDATE public.graph_change SET deletions = deletions + 1
WHERE id = 1 AND EXISTS (SELECT 1 FROM gone)`
}

// changedEntitiesText lists the entities changed at or after @since: their
// own rows, their asset rows, the edges and tags on them, and the tags on
// their edges. The asset rows are listed separately because a write that
// changes only an asset's attributes can leave its entity row untouched.
var changedEntitiesText = func() string {
	parts := []string{
		`SELECT entity_id FROM public.entity WHERE updated_at >= @since`,
		`SELECT from_entity_id FROM public.edge WHERE updated_at >= @since`,
		`SELECT to_entity_id FROM public.edge WHERE updated_at >= @since`,
		`SELECT entity_id FROM public.entity_tag WHERE updated_at >= @since`,
		`SELECT e.from_entity_id FROM public.edge_tag t JOIN public.edge e ON e.edge_id = t.edge_id
         WHERE t.updated_at >= @since`,
		`SELECT e.to_entity_id FROM public.edge_tag t JOIN public.edge e ON e.edge_id = t.edge_id
         WHERE t.updated_at >= @since`,
	}
	for _, at := range oam.AssetList {
		table := normalizeType(string(at))
		parts = append(parts, fmt.Sprintf(`SELECT e.entity_id FROM public.%[1]s a
         JOIN public.entity_type_lu t ON t.name = '%[1]s'
         JOIN public.entity e ON e.etype_id = t.id AND e.row_id = a.id
         WHERE a.updated_at >= @since`, table))
	}

	return strings.Join(parts, "\nUNION\n")
}()

// GraphChanges implements repository.ChangeReader.
func (r *PostgresRepository) GraphChanges(ctx context.Context, since time.Time) (*types.GraphChanges, error) {
	out := &types.GraphChanges{}
	j := NewRowJob(ctx, `SELECT localtimestamp, deletions FROM public.graph_change WHERE id = 1`, nil,
		func(row pgx.Row) error {
			return row.Scan(&out.Now, &out.Deletions)
		})
	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}
	if since.IsZero() {
		return out, nil
	}

	j = NewRowsJob(ctx, changedEntitiesText, pgx.NamedArgs{"since": since}, func(rows pgx.Rows) error {
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return err
			}

			out.EntityIDs = append(out.EntityIDs, strconv.FormatInt(id, 10))
		}
		return rows.Err()
	})
	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}
