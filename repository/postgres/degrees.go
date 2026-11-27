// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/owasp-amass/asset-db/types"
)

// DegreeHistograms implements repository.DegreeReader. The edges are
// grouped by the counted end and the label, which the (to_entity_id, label)
// and (from_entity_id, label, ...) indexes serve, in one scan for every
// label.
func (r *PostgresRepository) DegreeHistograms(ctx context.Context, direction string,
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

	out := map[string]types.DegreeHistogram{}
	j := NewRowsJob(ctx, `SELECT l, deg, count(*) FROM (
          SELECT lower(label::text) AS l, count(*) AS deg FROM public.edge
          WHERE label = ANY(@labels::citext[]) GROUP BY `+end+`, label) d
        GROUP BY l, deg`, pgx.NamedArgs{"labels": lower}, func(rows pgx.Rows) error {
		for rows.Next() {
			var l string
			var deg, n int64
			if err := rows.Scan(&l, &deg, &n); err != nil {
				return err
			}
			h := out[l]
			if h == nil {
				h = types.DegreeHistogram{}
				out[l] = h
			}
			h[int(deg)] = n
		}
		return rows.Err()
	})
	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}
