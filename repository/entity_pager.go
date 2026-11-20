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
	oam "github.com/owasp-amass/open-asset-model"
)

// EntityPager is an optional read-only repository capability that reads the
// entities of one asset type a bounded page at a time, so a whole-type sweep
// (such as the identity and person-named audits) scales without loading the
// type into memory or imposing an arbitrary cap.
//
// The cursor is a keyset position (entity_id ascending), not an offset, so
// entities written while a caller pages do not shift earlier pages: an entity
// already returned is never returned again.
type EntityPager interface {
	// EntitiesPage returns up to limit (1..1000) entities of atype after the
	// cursor, ordered by entity_id ascending. A nil after starts at the first
	// entity. since, when non-zero, limits to entities last seen at or after
	// it. next is nil on the last page; otherwise pass it back unchanged to
	// read the following page.
	EntitiesPage(ctx context.Context, atype oam.AssetType, since time.Time,
		after *types.EntityCursor, limit int) (entities []*types.Entity, next *types.EntityCursor, err error)
}

var (
	_ EntityPager = (*sqlite3.SqliteRepository)(nil)
	_ EntityPager = (*postgres.PostgresRepository)(nil)
)
