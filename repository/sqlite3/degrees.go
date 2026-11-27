// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"fmt"
	"strings"

	"github.com/owasp-amass/asset-db/internal/valuequery"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// DegreeHistograms implements repository.DegreeReader, in one scan for every
// label.
func (r *SqliteRepository) DegreeHistograms(ctx context.Context, direction string,
	labels []string) (map[string]types.DegreeHistogram, error) {
	if err := types.ValidateDegreeRead(direction, labels); err != nil {
		return nil, err
	}

	end := "to_entity_id"
	if direction == "out" {
		end = "from_entity_id"
	}
	lower := make([]string, len(labels))
	for i, l := range labels {
		lower[i] = strings.ToLower(strings.TrimSpace(l))
	}
	in, args := inClause(lower)
	// the reader keeps a prepared statement by name: each shape of the query
	// is named by its text
	q := `SELECT l, deg, COUNT(*) FROM (
          SELECT lower(label) AS l, COUNT(*) AS deg FROM edge
          WHERE label IN ` + in + ` GROUP BY ` + end + `, lower(label))
        GROUP BY l, deg`

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: q, SQLText: q, Args: args, Result: ch})
	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	out := map[string]types.DegreeHistogram{}
	for result.Rows.Next() {
		var l string
		var deg, n int64
		if err := result.Rows.Scan(&l, &deg, &n); err != nil {
			return nil, err
		}
		h := out[l]
		if h == nil {
			h = types.DegreeHistogram{}
			out[l] = h
		}
		h[int(deg)] = n
	}
	return out, result.Rows.Err()
}

// DegreeHistogramWhere implements repository.DegreeReader.
func (r *SqliteRepository) DegreeHistogramWhere(ctx context.Context, direction, label string, atype oam.AssetType,
	key, value string) (types.DegreeHistogram, error) {
	if err := types.ValidateDegreeRead(direction, []string{label}); err != nil {
		return nil, err
	}
	if err := types.ValidateDegreeFilter(value); err != nil {
		return nil, err
	}
	if err := valuequery.CheckKey(key); err != nil {
		return nil, err
	}
	table := validateAssetTable(string(atype))
	if table == "" {
		return nil, fmt.Errorf("unknown asset type %q", atype)
	}

	end := "to_entity_id"
	if direction == "out" {
		end = "from_entity_id"
	}
	// the same column the value search reads (see FindEntitiesByAttribute)
	valueExpr := fmt.Sprintf("json_extract(a.attrs, '$.%s')", key)
	if col := promotedColumn(table, key); col != "" {
		valueExpr = "a." + col
	}
	return r.histogram(ctx, fmt.Sprintf(`SELECT n, COUNT(*) FROM (
          SELECT COUNT(*) AS n FROM edge ed
          JOIN entity e ON e.entity_id = ed.%[1]s
          JOIN entity_type_lu t ON t.id = e.etype_id AND t.name = ?
          JOIN %[2]s a ON a.id = e.row_id
          WHERE ed.label = ? AND %[3]s = ? GROUP BY ed.%[1]s)
        GROUP BY n`, end, table, valueExpr), table, strings.ToLower(strings.TrimSpace(label)), value)
}
