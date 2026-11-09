// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitestfixture

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err, "Failed to load the synthetic fixture")
	assert.Len(t, f.Assets, 15, "Unexpected number of fixture assets")
	assert.Len(t, f.Relations, 12, "Unexpected number of fixture relations")
	assert.Len(t, f.Properties, 6, "Unexpected number of fixture properties")

	db := &recordingWriter{}
	report, err := Seed(context.Background(), db, f)
	assert.NoError(t, err, "Failed to seed the synthetic fixture")
	assert.Equal(t, len(f.Assets), report.Assets, "Seeded asset count does not match")
	assert.Equal(t, len(f.Relations), report.Relations, "Seeded relation count does not match")
	assert.Equal(t, len(f.Properties), report.Properties, "Seeded property count does not match")
	assert.Len(t, report.AssetIDs, 15, "Missing asset identity mappings")
	assert.Len(t, report.RelationIDs, 12, "Missing relation identity mappings")
}

func TestInvalidFixtureNoWrites(t *testing.T) {
	f, err := Load(fixtureDir())
	assert.NoError(t, err, "Failed to load the synthetic fixture")

	f.Relations = append(f.Relations,
		RelationRecord{ID: "edge-invalid", From: "org-fabrikam", To: "org-acme-holdings", Label: "domain"})
	db := &recordingWriter{}

	_, err = Seed(context.Background(), db, f)
	assert.Error(t, err, "An invalid relation should be rejected")
	assert.Zero(t, db.assets, "Validation should precede asset writes")
	assert.Zero(t, db.relations, "Validation should precede relation writes")
	assert.Zero(t, db.props, "Validation should precede property writes")
}

func TestCancelledSeedNoWrites(t *testing.T) {
	f, err := Load(fixtureDir())
	assert.NoError(t, err, "Failed to load the synthetic fixture")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	db := &recordingWriter{}

	_, err = Seed(ctx, db, f)
	assert.ErrorIs(t, err, context.Canceled, "A cancelled seed should return context.Canceled")
	assert.Zero(t, db.assets, "A cancelled seed should not write assets")
}
