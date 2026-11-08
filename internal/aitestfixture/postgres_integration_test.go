// SPDX-License-Identifier: Apache-2.0
package aitestfixture

import (
	"context"
	"os"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/postgres"
)

// TestSeedIntoDisposablePostgres deliberately requires an explicit test DSN.
// CI supplies an isolated service with a disposable amass_ai_fixture_* DB.
// Developers must never point this test at their normal Amass database.
func TestSeedIntoDisposablePostgres(t *testing.T) {
	dsn := os.Getenv("AMASS_AI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AMASS_AI_TEST_POSTGRES_DSN not configured")
	}
	if err := validateDisposablePostgresDSN(dsn); err != nil {
		t.Fatal(err)
	}
	fixture, err := Load(fixtureDir())
	if err != nil {
		t.Fatal(err)
	}
	repo, err := assetdb.New(postgres.Postgres, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	report, err := Seed(ctx, repo, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if report.Assets != 15 || report.Relations != 12 || report.Properties != 6 {
		t.Fatalf("unexpected counts: %+v", report)
	}
	parent, err := repo.FindEntityById(ctx, report.AssetIDs["org-acme-holdings"])
	if err != nil || parent == nil {
		t.Fatalf("parent missing: %v", err)
	}
	edges, err := repo.OutgoingEdges(ctx, parent, time.Time{}, "subsidiary")
	if err != nil || len(edges) != 2 {
		t.Fatalf("expected 2 subsidiaries, got %d: %v", len(edges), err)
	}
	edge, err := repo.FindEdgeById(ctx, report.RelationIDs["edge-acme-tech"])
	if err != nil || edge == nil {
		t.Fatalf("relation missing: %v", err)
	}
	tags, err := repo.FindEdgeTags(ctx, edge, time.Time{})
	if err != nil || len(tags) != 2 {
		t.Fatalf("expected two synthetic sources, got %d: %v", len(tags), err)
	}
}
