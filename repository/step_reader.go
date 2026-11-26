// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"time"

	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/asset-db/types"
)

// StepReader is an optional read-only repository capability for walks over
// the graph by type rules, such as an organization's controlled footprint.
// One call reads the edges a set of steps follows from many entities at
// once, with no limit per entity, so the walk reads only the edges it
// follows and asks once per round instead of once per entity.
type StepReader interface {
	// ReadSteps returns, each once, the edges whose source is one of ids and
	// that a forward step matches, and those whose destination is one of ids
	// and that a backward step matches (types.Step). It takes at most
	// MaxEntitiesByIds ids and types.MaxSteps steps. A non-zero since keeps
	// only edges last seen at or after it. The edges' entities carry their
	// IDs only.
	ReadSteps(ctx context.Context, ids []string, steps []types.Step, since time.Time) ([]*types.Edge, error)
}

var (
	_ StepReader = (*postgres.PostgresRepository)(nil)
	_ StepReader = (*sqlite3.SqliteRepository)(nil)
	_ StepReader = (*neo4j.NeoRepository)(nil)
)
