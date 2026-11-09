// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitestfixture

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSemanticAlternateRouteFixtureLoadsAndSeeds(t *testing.T) {
	f, err := Load(filepath.Join(fixtureDir(), "semantic"))
	assert.NoError(t, err, "Failed to load the semantic fixture")
	assert.Len(t, f.Assets, 11, "Unexpected number of semantic fixture assets")
	assert.Len(t, f.Relations, 10, "Unexpected number of semantic fixture relations")
	assert.Len(t, f.Properties, 11, "Unexpected number of semantic fixture properties")

	fromTo := map[string]int{}
	for _, r := range f.Relations {
		fromTo[r.From+"->"+r.To]++
	}
	assert.Equal(t, 1, fromTo["url-tech-main->fqdn-tech"], "Missing the main URL route to the FQDN")
	assert.Equal(t, 1, fromTo["url-tech-alternate->fqdn-tech"], "Missing the alternate URL route to the FQDN")

	sources := map[string]map[string]bool{}
	for _, p := range f.Properties {
		if p.Scope != "relation" || p.Kind != "source" {
			continue
		}
		if sources[p.Target] == nil {
			sources[p.Target] = map[string]bool{}
		}

		sources[p.Target][p.Name] = true
	}
	assert.Len(t, sources["edge-parent-tech"], 2, "Unexpected source count on edge-parent-tech")
	assert.Len(t, sources["edge-parent-europe"], 1, "Unexpected source count on edge-parent-europe")
	assert.Len(t, sources["edge-tech-web-main"], 1, "Unexpected source count on edge-tech-web-main")
	assert.Len(t, sources["edge-tech-web-alternate"], 2, "Unexpected source count on edge-tech-web-alternate")

	db := &recordingWriter{}
	report, err := Seed(context.Background(), db, f)
	assert.NoError(t, err, "Failed to seed the semantic fixture")
	assert.Equal(t, 11, report.Assets, "Seeded asset count does not match")
	assert.Equal(t, 10, report.Relations, "Seeded relation count does not match")
	assert.Equal(t, 11, report.Properties, "Seeded property count does not match")
}
