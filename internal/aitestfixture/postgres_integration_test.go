// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitestfixture

import (
	"context"
	"os"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/stretchr/testify/assert"
)

func TestSeedIntoDisposablePostgres(t *testing.T) {
	dsn := os.Getenv("AMASS_AI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AMASS_AI_TEST_POSTGRES_DSN not configured")
	}
	if err := validateDisposablePostgresDSN(dsn); err != nil {
		// Never seed a database that does not look disposable.
		t.Fatal(err)
	}

	fixture, err := Load(fixtureDir())
	assert.NoError(t, err, "Failed to load the synthetic fixture")

	repo, err := assetdb.New(postgres.Postgres, dsn)
	assert.NoError(t, err, "Failed to connect to the disposable PostgreSQL database")
	assert.NotNil(t, repo, "Asset database should not be nil")
	defer func() { _ = repo.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	report, err := Seed(ctx, repo, fixture)
	assert.NoError(t, err, "Failed to seed the synthetic fixture")
	assert.Equal(t, 15, report.Assets, "Unexpected number of seeded assets")
	assert.Equal(t, 12, report.Relations, "Unexpected number of seeded relations")
	assert.Equal(t, 6, report.Properties, "Unexpected number of seeded properties")

	parent, err := repo.FindEntityById(ctx, report.AssetIDs["org-acme-holdings"])
	assert.NoError(t, err, "Failed to find the parent organization")
	assert.NotNil(t, parent, "Parent organization should not be nil")

	edges, err := repo.OutgoingEdges(ctx, parent, time.Time{}, "subsidiary")
	assert.NoError(t, err, "Failed to read the subsidiary edges")
	assert.Len(t, edges, 2, "Expected two subsidiaries")

	edge, err := repo.FindEdgeById(ctx, report.RelationIDs["edge-acme-tech"])
	assert.NoError(t, err, "Failed to find the seeded relation")
	assert.NotNil(t, edge, "Seeded relation should not be nil")

	tags, err := repo.FindEdgeTags(ctx, edge, time.Time{})
	assert.NoError(t, err, "Failed to read the relation sources")
	assert.Len(t, tags, 2, "Expected two synthetic sources")

	assertLimitedEdges(t, ctx, repo, report.AssetIDs["org-acme-holdings"])
}
