// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// countDeletion is run after a DELETE in the same transaction (writeJob.Also):
// it adds one to the deletion count when the DELETE removed a row.
const countDeletion = `UPDATE graph_change SET deletions = deletions + 1 WHERE id = 1 AND changes() > 0`

// changeTimeLayout is how the store writes its times, so a since compares
// with them as text.
const changeTimeLayout = "2006-01-02 15:04:05.000"

// changedEntitiesText lists the entities changed at or after :since: their
// own rows, their asset rows, the edges and tags on them, and the tags on
// their edges. The asset rows are listed separately because a write that
// changes only an asset's attributes can leave its entity row untouched.
var changedEntitiesText = func() string {
	parts := []string{
		`SELECT entity_id FROM entity WHERE updated_at >= :since`,
		`SELECT from_entity_id FROM edge WHERE updated_at >= :since`,
		`SELECT to_entity_id FROM edge WHERE updated_at >= :since`,
		`SELECT entity_id FROM entity_tag WHERE updated_at >= :since`,
		`SELECT e.from_entity_id FROM edge_tag t JOIN edge e ON e.edge_id = t.edge_id WHERE t.updated_at >= :since`,
		`SELECT e.to_entity_id FROM edge_tag t JOIN edge e ON e.edge_id = t.edge_id WHERE t.updated_at >= :since`,
	}
	for _, at := range oam.AssetList {
		table := normalizeType(string(at))
		parts = append(parts, fmt.Sprintf(`SELECT e.entity_id FROM %[1]s a
         JOIN entity_type_lu t ON t.name = '%[1]s'
         JOIN entity e ON e.etype_id = t.id AND e.row_id = a.id
         WHERE a.updated_at >= :since`, table))
	}

	return strings.Join(parts, "\nUNION\n")
}()

// GraphChanges implements repository.ChangeReader.
func (r *SqliteRepository) GraphChanges(ctx context.Context, since time.Time) (*types.GraphChanges, error) {
	out := &types.GraphChanges{}
	var now string
	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "graph.changes.now",
		SQLText: `SELECT strftime('%Y-%m-%d %H:%M:%f', 'now'), deletions FROM graph_change WHERE id = 1`,
		Result:  ch,
	})
	res := <-ch
	if res.Err != nil {
		return nil, res.Err
	}
	if err := res.Row.Scan(&now, &out.Deletions); err != nil {
		return nil, err
	}
	t, err := time.Parse(changeTimeLayout, now)
	if err != nil {
		return nil, err
	}

	out.Now = t
	if since.IsZero() {
		return out, nil
	}

	rows := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{
		Ctx:     ctx,
		Name:    "graph.changes.entities",
		SQLText: changedEntitiesText,
		Args:    []any{sql.Named("since", since.UTC().Format(changeTimeLayout))},
		Result:  rows,
	})
	result := <-rows
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	for result.Rows.Next() {
		var id int64
		if err := result.Rows.Scan(&id); err != nil {
			return nil, err
		}

		out.EntityIDs = append(out.EntityIDs, strconv.FormatInt(id, 10))
	}

	return out, result.Rows.Err()
}
