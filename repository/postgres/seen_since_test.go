// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
)

// Within an enumeration, a sighting that brings nothing new does not
// rewrite the row; the first sighting in a later enumeration does.
func TestPostgresSeenSince(t *testing.T) {
	db := valueFinderRepo(t)
	ctx := context.Background()

	// no enumeration named: every sighting is recorded, as before
	first, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "seen.example"})
	if !assert.NoError(t, err, "creating the FQDN") {
		return
	}

	time.Sleep(20 * time.Millisecond)
	again, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "seen.example"})
	assert.NoError(t, err, "seeing the FQDN again")
	assert.Equal(t, first.ID, again.ID, "the same FQDN should be the same entity")
	assert.True(t, again.LastSeen.After(first.LastSeen),
		"without SetSeenSince every sighting updates the last-seen time")

	// a new enumeration: the first sighting in it is recorded
	db.SetSeenSince(time.Now())
	time.Sleep(20 * time.Millisecond)
	inRun, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "seen.example"})
	assert.NoError(t, err, "seeing the FQDN in the enumeration")
	assert.True(t, inRun.LastSeen.After(again.LastSeen),
		"the first sighting in an enumeration updates the last-seen time")

	// a repeat in the same enumeration keeps the row, and still returns it
	time.Sleep(20 * time.Millisecond)
	repeat, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "seen.example"})
	assert.NoError(t, err, "seeing the FQDN again in the enumeration")
	assert.Equal(t, inRun.ID, repeat.ID, "a skipped sighting should return the same entity")
	assert.True(t, repeat.LastSeen.Equal(inRun.LastSeen), "a repeat with nothing new keeps the last-seen time")

	// edges and tags behave the same, and their IDs come back
	ip, err := db.CreateAsset(ctx, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.9"), Type: "IPv4"})
	if !assert.NoError(t, err, "creating the IP address") {
		return
	}

	rel := &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1, TTL: 300}}
	e1, err := db.CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: inRun, ToEntity: ip})
	if !assert.NoError(t, err, "creating the edge") {
		return
	}

	// a resolver's TTL counts down; that alone is nothing new
	rel2 := &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1, TTL: 120}}
	e2, err := db.CreateEdge(ctx, &dbt.Edge{Relation: rel2, FromEntity: inRun, ToEntity: ip})
	assert.NoError(t, err, "seeing the edge again")
	assert.Equal(t, e1.ID, e2.ID, "the same DNS record should be the same edge")
	assert.True(t, e2.LastSeen.Equal(e1.LastSeen), "a repeated edge keeps its last-seen time in the enumeration")

	src := &oamgen.SourceProperty{Source: "DNS", Confidence: 100}
	t1, err := db.CreateEntityProperty(ctx, inRun, src)
	if !assert.NoError(t, err, "tagging the source") {
		return
	}

	t2, err := db.CreateEntityProperty(ctx, inRun, src)
	assert.NoError(t, err, "tagging the source again")
	assert.Equal(t, t1.ID, t2.ID, "the same source tag should come back")

	// a change is always written
	t3, err := db.CreateEntityProperty(ctx, inRun, &oamgen.SourceProperty{Source: "DNS", Confidence: 80})
	assert.NoError(t, err, "tagging the source with a new confidence")
	assert.Equal(t, t1.ID, t3.ID, "a source keeps one tag per entity")
	tags, err := db.FindEntityTags(ctx, inRun, time.Time{}, "DNS")
	if assert.NoError(t, err, "reading the source tags") && assert.Len(t, tags, 1, "one tag for the source") {
		assert.Equal(t, "80", tags[0].Property.Value(), "the latest confidence is kept")
	}
}

// Identity details the schema keeps: record types of DNS edges, and values
// longer than a B-tree index entry.
func TestPostgresEdgeAndTagIdentity(t *testing.T) {
	db := valueFinderRepo(t)
	ctx := context.Background()

	a, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "a.identity.example"})
	if !assert.NoError(t, err, "creating the first FQDN") {
		return
	}

	b, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "b.identity.example"})
	if !assert.NoError(t, err, "creating the second FQDN") {
		return
	}

	ns, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &oamdns.BasicDNSRelation{Name: "dns_record",
		Header: oamdns.RRHeader{RRType: 2, Class: 1}}, FromEntity: a, ToEntity: b})
	assert.NoError(t, err, "creating the NS edge")
	cname, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &oamdns.BasicDNSRelation{Name: "dns_record",
		Header: oamdns.RRHeader{RRType: 5, Class: 1}}, FromEntity: a, ToEntity: b})
	assert.NoError(t, err, "creating the CNAME edge")
	if ns != nil && cname != nil {
		assert.NotEqual(t, ns.ID, cname.ID, "records of two types between the same names are two edges")
	}

	long := strings.Repeat("v=spf1 include:_spf.example.com ", 120) // about 3.8 KB
	tag, err := db.CreateEntityProperty(ctx, a, &oamdns.DNSRecordProperty{PropertyName: "dns_record",
		Header: oamdns.RRHeader{RRType: 16, Class: 1}, Data: long})
	if assert.NoError(t, err, "a value longer than a B-tree entry should be stored") {
		// searches take at most 1,024 characters, so look for part of it
		found, _, err := db.FindEntitiesByTagValue(ctx, "FQDN", "dns_record", "include:_spf.example.com", true,
			time.Time{}, 5)
		assert.NoError(t, err, "finding the entity by part of the long value")
		assert.Len(t, found, 1, "the long value should find its entity")
		short, _, err := db.FindEntitiesByTagValue(ctx, "FQDN", "dns_record", "v=spf1 -all", false, time.Time{}, 5)
		assert.NoError(t, err, "an exact search for a value no tag holds")
		assert.Empty(t, short, "an exact search should match whole values only")
		again, err := db.CreateEntityProperty(ctx, a, &oamdns.DNSRecordProperty{PropertyName: "dns_record",
			Header: oamdns.RRHeader{RRType: 16, Class: 1}, Data: long})
		assert.NoError(t, err, "storing the long value again")
		if again != nil {
			assert.Equal(t, tag.ID, again.ID, "the same long value should be the same tag")
		}
	}
}
