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

// ValueFinder is an optional read-only repository capability for
// correlating evidence: it finds the other entities that carry a value one
// entity has, such as the same DNS TXT verification token or the same
// certificate key identifier. Rows are limited at the database layer, and
// more=true means at least one further match exists.
type ValueFinder interface {
	// FindEntitiesByTagValue finds entities of atype with a tag whose
	// property name is name and whose value equals value, or contains it
	// (case-insensitive) when contains is set.
	FindEntitiesByTagValue(ctx context.Context, atype oam.AssetType, name, value string, contains bool, since time.Time, limit int) ([]*types.Entity, bool, error)
	// FindEntitiesByAttribute finds entities of atype whose stored asset
	// attribute key (a JSON field such as subject_key_id) equals value.
	FindEntitiesByAttribute(ctx context.Context, atype oam.AssetType, key, value string, since time.Time, limit int) ([]*types.Entity, bool, error)
}

var (
	_ ValueFinder = (*sqlite3.SqliteRepository)(nil)
	_ ValueFinder = (*postgres.PostgresRepository)(nil)
	_ ValueFinder = (*neo4j.NeoRepository)(nil)
)
