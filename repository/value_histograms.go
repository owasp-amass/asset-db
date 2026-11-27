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

// ValueHistogramReader is implemented by repositories that can count how
// many entities hold each stored value: the distribution a tool uses to
// tell a value held by unusually many assets (a provider's verification
// token, a shared certificate key) from an ordinary one. Each histogram is
// holders -> values with that many holders.
type ValueHistogramReader interface {
	// TagValueHistogram counts, over the entities of atype with a tag named
	// name, how many entities hold each exact tag value; with prefixes,
	// only values starting with one of them (case-insensitive) count.
	TagValueHistogram(ctx context.Context, atype oam.AssetType, name string, prefixes []string) (types.DegreeHistogram, error)
	// AttributeValueHistogram counts, over the entities of atype, how many
	// hold each exact value of the stored attribute key.
	AttributeValueHistogram(ctx context.Context, atype oam.AssetType, key string) (types.DegreeHistogram, error)
}

var (
	_ ValueHistogramReader = (*postgres.PostgresRepository)(nil)
	_ ValueHistogramReader = (*sqlite3.SqliteRepository)(nil)
)
