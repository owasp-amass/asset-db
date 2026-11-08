// SPDX-License-Identifier: Apache-2.0
package aitestfixture

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// RecordingWriter verifies that a fixture can be seeded using only the existing
// repository interface, without relying on a particular database implementation.
type recordingWriter struct{ assets, relations, props int }

func (r *recordingWriter) CreateAsset(_ context.Context, a oam.Asset) (*types.Entity, error) {
	r.assets++
	return &types.Entity{ID: a.Key(), Asset: a}, nil
}
func (r *recordingWriter) CreateEdge(_ context.Context, e *types.Edge) (*types.Edge, error) {
	r.relations++
	e.ID = e.FromEntity.ID + "/" + e.ToEntity.ID
	return e, nil
}
func (r *recordingWriter) CreateEntityProperty(_ context.Context, _ *types.Entity, _ oam.Property) (*types.EntityTag, error) {
	r.props++
	return &types.EntityTag{}, nil
}
func (r *recordingWriter) CreateEdgeProperty(_ context.Context, _ *types.Edge, _ oam.Property) (*types.EdgeTag, error) {
	r.props++
	return &types.EdgeTag{}, nil
}
func fixtureDir() string { return filepath.Join("..", "..", "testdata", "ai") }
func TestLoadAndSeedSynthetic(t *testing.T) {
	f, err := Load(fixtureDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Assets) != 15 || len(f.Relations) != 12 || len(f.Properties) != 6 {
		t.Fatalf("unexpected fixture size: %+v", f)
	}
	db := &recordingWriter{}
	report, err := Seed(context.Background(), db, f)
	if err != nil {
		t.Fatal(err)
	}
	if report.Assets != len(f.Assets) || report.Relations != len(f.Relations) || report.Properties != len(f.Properties) {
		t.Fatalf("counts: %+v", report)
	}
	if len(report.AssetIDs) != 15 || len(report.RelationIDs) != 12 {
		t.Fatalf("missing identity mappings: %+v", report)
	}
}
func TestInvalidFixtureNoWrites(t *testing.T) {
	f, err := Load(fixtureDir())
	if err != nil {
		t.Fatal(err)
	}
	f.Relations = append(f.Relations, RelationRecord{ID: "edge-invalid", From: "org-fabrikam", To: "org-acme-holdings", Label: "domain"})
	db := &recordingWriter{}
	if _, err := Seed(context.Background(), db, f); err == nil {
		t.Fatal("invalid relation accepted")
	}
	if db.assets != 0 || db.relations != 0 || db.props != 0 {
		t.Fatal("validation did not precede mutations")
	}
}
func TestCancelledSeedNoWrites(t *testing.T) {
	f, err := Load(fixtureDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	db := &recordingWriter{}
	_, err = Seed(ctx, db, f)
	if !errors.Is(err, context.Canceled) || db.assets != 0 {
		t.Fatalf("ctx=%v writes=%d", err, db.assets)
	}
}
