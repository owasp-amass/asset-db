// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/owasp-amass/asset-db/internal/valuequery"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// TagValueHistogram implements repository.ValueHistogramReader.
func (r *PostgresRepository) TagValueHistogram(ctx context.Context, atype oam.AssetType, name string,
	prefixes []string) (types.DegreeHistogram, error) {
	if r == nil || r.DB == nil {
		return nil, errors.New("missing PostgreSQL reader")
	}
	if err := valuequery.CheckHistogram(atype, name, prefixes); err != nil {
		return nil, err
	}

	args := []any{normalizeType(string(atype)), name}
	match := ""
	if len(prefixes) > 0 {
		pats := make([]string, len(prefixes))
		for i, p := range prefixes {
			pats[i] = valuequery.LikePrefix(p)
		}
		args = append(args, pats)
		match = " AND lower(g.property_value) LIKE ANY($3::text[])"
	}
	return r.histogram(ctx, `SELECT n, count(*) FROM (
          SELECT count(DISTINCT g.entity_id) AS n FROM public.entity_tag g
          JOIN public.entity e ON e.entity_id = g.entity_id
          JOIN public.entity_type_lu t ON t.id = e.etype_id AND t.name = $1
          WHERE g.property_name = $2`+match+` GROUP BY g.property_value) v
        GROUP BY n`, args...)
}

// AttributeValueHistogram implements repository.ValueHistogramReader.
func (r *PostgresRepository) AttributeValueHistogram(ctx context.Context, atype oam.AssetType,
	key string) (types.DegreeHistogram, error) {
	if r == nil || r.DB == nil {
		return nil, errors.New("missing PostgreSQL reader")
	}
	if err := valuequery.CheckHistogram(atype, key, nil); err != nil {
		return nil, err
	}
	if err := valuequery.CheckKey(key); err != nil {
		return nil, err
	}
	table := assetTable(atype)
	if table == "" {
		return nil, fmt.Errorf("unknown asset type %q", atype)
	}

	// the same column the value search reads (see FindEntitiesByAttribute)
	valueExpr := fmt.Sprintf("a.attrs->>'%s'", key)
	if col := promotedColumn(table, key); col != "" {
		valueExpr = "a." + col
	}
	return r.histogram(ctx, fmt.Sprintf(`SELECT n, count(*) FROM (
          SELECT count(*) AS n FROM public.entity e
          JOIN public.entity_type_lu t ON t.id = e.etype_id AND t.name = $1
          JOIN public.%s a ON a.id = e.row_id
          WHERE coalesce(%s, '') <> '' GROUP BY %s) v
        GROUP BY n`, table, valueExpr, valueExpr), table)
}

// histogram runs a query selecting (holders, values) rows.
func (r *PostgresRepository) histogram(ctx context.Context, query string, args ...any) (types.DegreeHistogram, error) {
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanHistogram(rows)
}

// scanHistogram reads (holders, values) rows into a histogram.
func scanHistogram(rows *sql.Rows) (types.DegreeHistogram, error) {
	out := types.DegreeHistogram{}
	for rows.Next() {
		var n, values int64
		if err := rows.Scan(&n, &values); err != nil {
			return nil, err
		}
		out[int(n)] = values
	}
	return out, rows.Err()
}
