// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"

	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// DegreeReader is implemented by repositories that can count, for relation
// labels, how many edges each entity has: the distribution a tool uses to
// tell a value held by unusually many assets (a provider's phone number,
// say) from an ordinary one.
type DegreeReader interface {
	// DegreeHistograms returns, for each of labels (compared without case and
	// keyed in lower case), how many entities have each number of edges with
	// the label in direction: "in" counts the edges to an entity, "out" the
	// edges from it. Entities without such edges are not counted, and a
	// label no edge has is absent.
	DegreeHistograms(ctx context.Context, direction string, labels []string) (map[string]types.DegreeHistogram, error)
	// DegreeHistogramWhere is one label's histogram, counting only entities of
	// atype whose stored attribute key equals value: the fingerprint
	// Identifiers of one id_type, say.
	DegreeHistogramWhere(ctx context.Context, direction, label string, atype oam.AssetType, key,
		value string) (types.DegreeHistogram, error)
}

var (
	_ DegreeReader = (*postgres.PostgresRepository)(nil)
	_ DegreeReader = (*sqlite3.SqliteRepository)(nil)
)
