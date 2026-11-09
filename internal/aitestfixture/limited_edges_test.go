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
)

func assertLimitedEdges(t *testing.T, ctx context.Context, db repository.Repository, parentID string) {
	t.Helper()
	reader, ok := db.(repository.LimitedEdgeReader)
	if !ok {
		t.Fatal("repository does not implement bounded edge reads")
	}
	parent, err := db.FindEntityById(ctx, parentID)
	if err != nil {
		t.Fatal(err)
	}
	edges, more, err := reader.ReadEdgesLimited(ctx, parent, "out", time.Time{}, 1, "subsidiary")
	if err != nil || len(edges) != 1 || !more {
		t.Fatalf("expected one edge and more=true: edges=%d more=%v err=%v", len(edges), more, err)
	}
	edges, more, err = reader.ReadEdgesLimited(ctx, parent, "out", time.Time{}, 2, "subsidiary")
	if err != nil || len(edges) != 2 || more {
		t.Fatalf("expected two edges and no remainder: edges=%d more=%v err=%v", len(edges), more, err)
	}
	edges, more, err = reader.ReadEdgesLimited(ctx, parent, "in", time.Time{}, 2, "subsidiary")
	if err != nil || len(edges) != 0 || more {
		t.Fatalf("expected empty inbound results: edges=%d more=%v err=%v", len(edges), more, err)
	}
	if _, _, err = reader.ReadEdgesLimited(ctx, parent, "out", time.Time{}, 0); err == nil {
		t.Fatal("zero limit unexpectedly accepted")
	}
	if _, _, err = reader.ReadEdgesLimited(ctx, parent, "unsafe", time.Time{}, 10); err == nil {
		t.Fatal("invalid direction accepted")
	}
}

func TestBoundedSQLiteEdges(t *testing.T) {
	f, err := Load(fixtureDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "limited.db"))
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
	assertLimitedEdges(t, ctx, db, report.AssetIDs["org-acme-holdings"])
}
