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

// RunRecorder is implemented by repositories that keep a record of the
// collection runs that wrote to them, from any tool (types.CollectionRun).
type RunRecorder interface {
	// StartRun records a run as running and returns it with its ID. A zero
	// StartedAt is now.
	StartRun(ctx context.Context, run *types.CollectionRun) (*types.CollectionRun, error)
	// FinishRun ends a running run with status (finished, stopped or
	// failed) at finished, or now when zero.
	FinishRun(ctx context.Context, id, status string, finished time.Time) (*types.CollectionRun, error)
	// FindRunById returns one run.
	FindRunById(ctx context.Context, id string) (*types.CollectionRun, error)
	// FindRuns returns the runs started at or after since (all runs when
	// zero), newest first, at most limit (all when zero), of the named tools
	// (any tool when none are named).
	FindRuns(ctx context.Context, since time.Time, limit int, tools ...string) ([]*types.CollectionRun, error)
}

var (
	_ RunRecorder = (*postgres.PostgresRepository)(nil)
	_ RunRecorder = (*sqlite3.SqliteRepository)(nil)
	_ RunRecorder = (*neo4j.NeoRepository)(nil)
)
