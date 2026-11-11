// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"

	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// AssetReplacer is an optional repository capability for correcting stored
// data. CreateAsset keeps a stored value when the asset leaves a field
// empty; ReplaceAsset stores the asset's content exactly, so a field the
// asset leaves empty is cleared. It only replaces an existing entity with
// the same key and never creates one. Organization is supported; other
// types return an error.
type AssetReplacer interface {
	ReplaceAsset(ctx context.Context, asset oam.Asset) (*types.Entity, error)
}

var (
	_ AssetReplacer = (*sqlite3.SqliteRepository)(nil)
	_ AssetReplacer = (*postgres.PostgresRepository)(nil)
	_ AssetReplacer = (*neo4j.NeoRepository)(nil)
)
