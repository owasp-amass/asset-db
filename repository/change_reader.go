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

// ChangeReader is an optional read-only repository capability for readers
// that keep what they read between reads, such as a cache that lasts across
// an enumeration's attribution passes. One call says which entities changed
// since a time, and how many deletions the store has ever made, so the
// reader can drop what changed and start over after a deletion.
type ChangeReader interface {
	// GraphChanges returns the deletion count, the store's time, and, when
	// since is not zero, the entities whose rows, edges or tags were created
	// or updated at or after since (types.GraphChanges). A write whose
	// transaction commits after Now can carry an earlier time, so a reader
	// passes back a since somewhat before the last Now.
	GraphChanges(ctx context.Context, since time.Time) (*types.GraphChanges, error)
}

var (
	_ ChangeReader = (*postgres.PostgresRepository)(nil)
	_ ChangeReader = (*sqlite3.SqliteRepository)(nil)
	_ ChangeReader = (*neo4j.NeoRepository)(nil)
)
