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
)

func TestSeedIntoDisposableSQLite(t *testing.T) {
	f, err := Load(fixtureDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "test-fixture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := Seed(ctx, db, f)
	if err != nil {
		t.Fatal(err)
	}
	e, err := db.FindEntityById(ctx, report.AssetIDs["org-acme-holdings"])
	if err != nil || e == nil {
		t.Fatalf("parent not found: %v", err)
	}
	edges, err := db.OutgoingEdges(ctx, e, time.Time{}, "subsidiary")
	if err != nil || len(edges) != 2 {
		t.Fatalf("expected two subsidiary edges, got %d: %v", len(edges), err)
	}
	id := report.RelationIDs["edge-acme-tech"]
	edge, err := db.FindEdgeById(ctx, id)
	if err != nil || edge == nil {
		t.Fatalf("edge not found: %v", err)
	}
	tags, err := db.FindEdgeTags(ctx, edge, time.Time{})
	if err != nil || len(tags) < 2 {
		t.Fatalf("expected two independent sources: %d: %v", len(tags), err)
	}
}
