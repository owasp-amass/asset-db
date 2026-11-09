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
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/stretchr/testify/assert"
)

func assertLimitedEdges(t *testing.T, ctx context.Context, db repository.Repository, parentID string) {
	t.Helper()

	reader, ok := db.(repository.LimitedEdgeReader)
	assert.True(t, ok, "Repository does not implement bounded edge reads")
	if !ok {
		return
	}

	parent, err := db.FindEntityById(ctx, parentID)
	assert.NoError(t, err, "Failed to find the parent organization")
	assert.NotNil(t, parent, "Parent organization should not be nil")

	edges, more, err := reader.ReadEdgesLimited(ctx, parent, "out", time.Time{}, 1, "subsidiary")
	assert.NoError(t, err, "Failed to read one bounded edge")
	assert.Len(t, edges, 1, "A limit of one should return one edge")
	assert.True(t, more, "More edges should be reported beyond a limit of one")

	edges, more, err = reader.ReadEdgesLimited(ctx, parent, "out", time.Time{}, 2, "subsidiary")
	assert.NoError(t, err, "Failed to read two bounded edges")
	assert.Len(t, edges, 2, "A limit of two should return both edges")
	assert.False(t, more, "No edges should remain beyond a limit of two")

	edges, more, err = reader.ReadEdgesLimited(ctx, parent, "in", time.Time{}, 2, "subsidiary")
	assert.NoError(t, err, "Failed to read inbound bounded edges")
	assert.Empty(t, edges, "The parent should have no inbound subsidiary edges")
	assert.False(t, more, "No inbound edges should remain")

	_, _, err = reader.ReadEdgesLimited(ctx, parent, "out", time.Time{}, 0)
	assert.Error(t, err, "A zero limit should be rejected")

	_, _, err = reader.ReadEdgesLimited(ctx, parent, "unsafe", time.Time{}, 10)
	assert.Error(t, err, "An invalid direction should be rejected")
}

func TestBoundedSQLiteEdges(t *testing.T) {
	f, err := Load(fixtureDir())
	assert.NoError(t, err, "Failed to load the synthetic fixture")

	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "limited.db"))
	assert.NoError(t, err, "Failed to create the sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := Seed(ctx, db, f)
	assert.NoError(t, err, "Failed to seed the synthetic fixture")

	assertLimitedEdges(t, ctx, db, report.AssetIDs["org-acme-holdings"])
}
