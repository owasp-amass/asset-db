// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"fmt"
	"testing"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Degree histograms count, per label, how many entities have each number of
// edges in a direction.
func TestSQLiteDegreeHistograms(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err)
	defer teardownTempSQLite(db, dir)
	ctx := context.Background()

	fqdn := func(name string) *dbt.Entity {
		e, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
		require.NoError(t, err)
		return e
	}
	var src []*dbt.Entity
	for i := range 3 {
		src = append(src, fqdn(fmt.Sprintf("s%d.degrees.example", i)))
	}
	hub, one, two := fqdn("hub.degrees.example"), fqdn("one.degrees.example"), fqdn("two.degrees.example")
	link := func(from, to *dbt.Entity) {
		_, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &oamgen.SimpleRelation{Name: "node"},
			FromEntity: from, ToEntity: to})
		require.NoError(t, err)
	}
	// the hub has three edges in; one and two have one each
	for _, s := range src {
		link(s, hub)
	}
	link(src[0], one)
	link(src[1], two)

	in, err := db.DegreeHistograms(ctx, "in", []string{"NODE", "nothing"})
	require.NoError(t, err)
	assert.Equal(t, map[string]dbt.DegreeHistogram{"node": {1: 2, 3: 1}}, in,
		"labels match without case, and a label no edge has is absent")
	out, err := db.DegreeHistograms(ctx, "out", []string{"node"})
	require.NoError(t, err)
	assert.Equal(t, map[string]dbt.DegreeHistogram{"node": {1: 1, 2: 2}}, out)

	_, err = db.DegreeHistograms(ctx, "both", []string{"node"})
	assert.Error(t, err, "only in or out is counted")
	_, err = db.DegreeHistograms(ctx, "in", nil)
	assert.Error(t, err, "a read names a label")
}

// A filtered degree histogram counts only the entities whose attribute
// equals the value asked for: fingerprints of one kind.
func TestSQLiteDegreeHistogramWhere(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err)
	defer teardownTempSQLite(db, dir)
	ctx := context.Background()

	url := func(host string) *dbt.Entity {
		e, err := db.CreateAsset(ctx, &oamurl.URL{Raw: "https://" + host + "/", Scheme: "https", Host: host,
			Path: "/"})
		require.NoError(t, err)
		return e
	}
	ident := func(value, kind string) *dbt.Entity {
		e, err := db.CreateAsset(ctx, &oamgen.Identifier{UniqueID: kind + ":" + value, ID: value, Type: kind})
		require.NoError(t, err)
		return e
	}
	link := func(from, to *dbt.Entity) {
		_, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &oamgen.SimpleRelation{Name: "fingerprint"},
			FromEntity: from, ToEntity: to})
		require.NoError(t, err)
	}
	var urls []*dbt.Entity
	for i := range 4 {
		urls = append(urls, url(fmt.Sprintf("u%d.degrees-where.example", i)))
	}
	// one favicon on three pages, another on one, and a title on two
	shared, alone, title := ident("111", "degree_favicon"), ident("222", "degree_favicon"), ident("t", "degree_title")
	for _, u := range urls[:3] {
		link(u, shared)
	}
	link(urls[3], alone)
	link(urls[0], title)
	link(urls[1], title)

	h, err := db.DegreeHistogramWhere(ctx, "in", "fingerprint", oam.Identifier, "id_type", "degree_favicon")
	require.NoError(t, err)
	assert.Equal(t, dbt.DegreeHistogram{3: 1, 1: 1}, h)
	h, err = db.DegreeHistogramWhere(ctx, "in", "fingerprint", oam.Identifier, "id_type", "degree_title")
	require.NoError(t, err)
	assert.Equal(t, dbt.DegreeHistogram{2: 1}, h)

	_, err = db.DegreeHistogramWhere(ctx, "in", "fingerprint", oam.Identifier, "x') OR 1=1 --", "v")
	assert.Error(t, err, "an attribute key that is not an identifier")
	_, err = db.DegreeHistogramWhere(ctx, "in", "fingerprint", oam.Identifier, "id_type", "")
	assert.Error(t, err, "an empty value")
}
