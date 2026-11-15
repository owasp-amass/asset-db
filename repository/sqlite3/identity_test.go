// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DNS edges are distinct per record type, and a source keeps one tag per
// entity holding its latest confidence.
func TestSQLiteEdgeAndSourceIdentity(t *testing.T) {
	db, dir, err := setupTempSQLite()
	require.NoError(t, err, "creating the database")
	defer teardownTempSQLite(db, dir)
	ctx := context.Background()

	a, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "a.identity.example"})
	require.NoError(t, err, "creating the first FQDN")
	b, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "b.identity.example"})
	require.NoError(t, err, "creating the second FQDN")

	edge := func(rrtype, ttl int) *dbt.Edge {
		e, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &oamdns.BasicDNSRelation{Name: "dns_record",
			Header: oamdns.RRHeader{RRType: rrtype, Class: 1, TTL: ttl}}, FromEntity: a, ToEntity: b})
		require.NoError(t, err, "creating the edge of record type %d", rrtype)
		return e
	}
	ns, cname, again := edge(2, 300), edge(5, 300), edge(2, 120)
	assert.NotEqual(t, ns.ID, cname.ID, "records of two types between the same names are two edges")
	assert.Equal(t, ns.ID, again.ID, "the same record seen again is the same edge")

	edges, err := db.OutgoingEdges(ctx, a, time.Time{}, "dns_record")
	assert.NoError(t, err, "reading the edges")
	assert.Len(t, edges, 2, "both record types are read back")

	t1, err := db.CreateEntityProperty(ctx, a, &oamgen.SourceProperty{Source: "DNS", Confidence: 100})
	require.NoError(t, err, "tagging the source")
	t2, err := db.CreateEntityProperty(ctx, a, &oamgen.SourceProperty{Source: "DNS", Confidence: 80})
	require.NoError(t, err, "tagging the source with a new confidence")
	assert.Equal(t, t1.ID, t2.ID, "a source keeps one tag per entity")

	tags, err := db.FindEntityTags(ctx, a, time.Time{}, "DNS")
	if assert.NoError(t, err, "reading the source tags") && assert.Len(t, tags, 1, "one tag for the source") {
		assert.Equal(t, "80", tags[0].Property.Value(), "the latest confidence is kept")
	}

	et1, err := db.CreateEdgeProperty(ctx, ns, &oamgen.SourceProperty{Source: "DNS", Confidence: 100})
	require.NoError(t, err, "tagging the edge's source")
	et2, err := db.CreateEdgeProperty(ctx, ns, &oamgen.SourceProperty{Source: "DNS", Confidence: 90})
	require.NoError(t, err, "tagging the edge's source again")
	assert.Equal(t, et1.ID, et2.ID, "a source keeps one tag per edge")
}
