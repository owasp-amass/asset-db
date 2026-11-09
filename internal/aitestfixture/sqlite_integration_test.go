// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitestfixture

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/stretchr/testify/assert"
)

func TestSeedIntoDisposableSQLite(t *testing.T) {
	f, err := Load(fixtureDir())
	assert.NoError(t, err, "Failed to load the synthetic fixture")

	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "test-fixture.db"))
	assert.NoError(t, err, "Failed to create the sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := Seed(ctx, db, f)
	assert.NoError(t, err, "Failed to seed the synthetic fixture")

	e, err := db.FindEntityById(ctx, report.AssetIDs["org-acme-holdings"])
	assert.NoError(t, err, "Failed to find the parent organization")
	assert.NotNil(t, e, "Parent organization should not be nil")

	edges, err := db.OutgoingEdges(ctx, e, time.Time{}, "subsidiary")
	assert.NoError(t, err, "Failed to read the subsidiary edges")
	assert.Len(t, edges, 2, "Expected two subsidiary edges")

	edge, err := db.FindEdgeById(ctx, report.RelationIDs["edge-acme-tech"])
	assert.NoError(t, err, "Failed to find the seeded relation")
	assert.NotNil(t, edge, "Seeded relation should not be nil")

	tags, err := db.FindEdgeTags(ctx, edge, time.Time{})
	assert.NoError(t, err, "Failed to read the relation sources")
	assert.GreaterOrEqual(t, len(tags), 2, "Expected two independent sources")
}
