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
	oam "github.com/owasp-amass/open-asset-model"
)

// CoKeyedGrouper is an optional read-only repository capability that supports
// duplicate-candidate generation at scale. Instead of loading every entity of a
// type into memory and pairing them, a caller asks the database to group the
// entities that already share a blocking key (a common identifier, contact
// record, registration, or tag). Each returned group holds the entity ids that
// share one key, so the caller scores only genuine candidates.
type CoKeyedGrouper interface {
	// CoKeyedGroups returns the groups of entities of atype that share the
	// blocking key named by key. param supplies the tag property name for
	// CoKeyTag and is ignored otherwise. Only groups of 2..maxGroup members are
	// returned: a key shared by more than maxGroup entities is too common to
	// discriminate duplicates and is dropped. When since is non-zero, only keys
	// whose backing row (edge, organization, or tag) was last seen at or after
	// it are considered, so an incremental sweep revisits only recent changes.
	CoKeyedGroups(ctx context.Context, atype oam.AssetType, key types.CoKey, param string, maxGroup int, since time.Time) ([]types.CoKeyGroup, error)
}

var (
	_ CoKeyedGrouper = (*sqlite3.SqliteRepository)(nil)
	_ CoKeyedGrouper = (*postgres.PostgresRepository)(nil)
	_ CoKeyedGrouper = (*neo4j.NeoRepository)(nil)
)
