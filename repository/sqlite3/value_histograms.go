// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/owasp-amass/asset-db/internal/valuequery"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// TagValueHistogram implements repository.ValueHistogramReader.
func (r *SqliteRepository) TagValueHistogram(ctx context.Context, atype oam.AssetType, name string,
	prefixes []string) (types.DegreeHistogram, error) {
	if r == nil || r.rpool == nil {
		return nil, errors.New("missing SQLite reader")
	}
	if err := valuequery.CheckHistogram(atype, name, prefixes); err != nil {
		return nil, err
	}

	args := []any{normalizeType(string(atype)), name}
	match := ""
	if len(prefixes) > 0 {
		likes := make([]string, len(prefixes))
		for i, p := range prefixes {
			likes[i] = `lower(g.property_value) LIKE ? ESCAPE '\'`
			args = append(args, valuequery.LikePrefix(p))
		}
		match = " AND (" + strings.Join(likes, " OR ") + ")"
	}
	return r.histogram(ctx, `SELECT n, COUNT(*) FROM (
          SELECT COUNT(DISTINCT g.entity_id) AS n FROM entity_tag g
          JOIN entity e ON e.entity_id = g.entity_id
          JOIN entity_type_lu t ON t.id = e.etype_id AND t.name = ?
          WHERE g.property_name = ?`+match+` GROUP BY g.property_value)
        GROUP BY n`, args...)
}

// AttributeValueHistogram implements repository.ValueHistogramReader.
func (r *SqliteRepository) AttributeValueHistogram(ctx context.Context, atype oam.AssetType,
	key string) (types.DegreeHistogram, error) {
	if r == nil || r.rpool == nil {
		return nil, errors.New("missing SQLite reader")
	}
	if err := valuequery.CheckHistogram(atype, key, nil); err != nil {
		return nil, err
	}
	if err := valuequery.CheckKey(key); err != nil {
		return nil, err
	}
	table := validateAssetTable(string(atype))
	if table == "" {
		return nil, fmt.Errorf("unknown asset type %q", atype)
	}

	// the same column the value search reads (see FindEntitiesByAttribute)
	valueExpr := fmt.Sprintf("json_extract(a.attrs, '$.%s')", key)
	if col := promotedColumn(table, key); col != "" {
		valueExpr = "a." + col
	}
	return r.histogram(ctx, fmt.Sprintf(`SELECT n, COUNT(*) FROM (
          SELECT COUNT(*) AS n FROM entity e
          JOIN entity_type_lu t ON t.id = e.etype_id AND t.name = ?
          JOIN %s a ON a.id = e.row_id
          WHERE coalesce(%s, '') <> '' GROUP BY %s)
        GROUP BY n`, table, valueExpr, valueExpr), table)
}

// histogram runs a query selecting (holders, values) rows; the reader keeps a
// prepared statement by name, so each query is named by its text.
func (r *SqliteRepository) histogram(ctx context.Context, query string, args ...any) (types.DegreeHistogram, error) {
	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{Ctx: ctx, Name: query, SQLText: query, Args: args, Result: ch})
	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	out := types.DegreeHistogram{}
	for result.Rows.Next() {
		var n, values int64
		if err := result.Rows.Scan(&n, &values); err != nil {
			return nil, err
		}
		out[int(n)] = values
	}
	return out, result.Rows.Err()
}
