// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"time"

	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/asset-db/types"
)

// LimitedEdgeReader is an optional read-only repository capability.
// Unlike IncomingEdges/OutgoingEdges it limits rows at the database layer.
// A returned more=true means at least one further matching edge exists.
// It returns only the first page in latest-observation order; EdgePager
// reads the pages after it.
type LimitedEdgeReader interface {
	ReadEdgesLimited(ctx context.Context, entity *types.Entity, direction string, since time.Time, limit int, labels ...string) ([]*types.Edge, bool, error)
}

// EdgePager is an optional read-only repository capability that reads an
// entity's edges one bounded page at a time.
//
// The cursor is a keyset position, not an offset, so edges written while a
// caller pages do not shift later pages. An edge created or updated during
// the read moves ahead of the cursor and is not returned by the remaining
// pages; an edge already returned is never returned again.
type EdgePager interface {
	// ReadEdgesPage returns up to limit (1..500) edges of entity in one
	// direction ("in", "out" or "both") after the cursor, newest first. A nil
	// after starts at the newest edge. next is nil on the last page;
	// otherwise pass it back unchanged to read the following page.
	ReadEdgesPage(ctx context.Context, entity *types.Entity, direction string, since time.Time,
		after *types.EdgeCursor, limit int, labels ...string) (edges []*types.Edge, next *types.EdgeCursor, err error)
}

var (
	_ EdgePager = (*sqlite3.SqliteRepository)(nil)
	_ EdgePager = (*postgres.PostgresRepository)(nil)
)
