// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"testing"

	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
)

func TestSameRelation(t *testing.T) {
	ns := &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 2, Class: 1, TTL: 300}}
	nsLater := &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 2, Class: 1, TTL: 120}}
	cname := &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 5, Class: 1, TTL: 300}}

	assert.True(t, sameRelation(ns, nsLater), "a record seen with a lower TTL is the same edge")
	assert.True(t, sameRelation(ns, *nsLater), "a relation read back by value matches one written by pointer")
	assert.False(t, sameRelation(ns, cname), "an NS and a CNAME record are two edges")

	mx := &oamdns.PrefDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 15, Class: 1}, Preference: 10}
	mx2 := &oamdns.PrefDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 15, Class: 1, TTL: 5},
		Preference: 20}
	assert.True(t, sameRelation(mx, mx2), "an MX record whose preference changed is the same edge, as in SQL")

	node := &oamgen.SimpleRelation{Name: "node"}
	assert.True(t, sameRelation(node, &oamgen.SimpleRelation{Name: "node"}), "simple relations compare whole")
	assert.False(t, sameRelation(node, &oamgen.SimpleRelation{Name: "contains"}), "another label is another edge")
	assert.False(t, sameRelation(node, nil), "a missing relation matches nothing")
}

func TestCertificateContentFilter(t *testing.T) {
	filter, err := defaultContentFilter(&oamcert.TLSCertificate{SerialNumber: "1", IssuerCommonName: "printer.example.edu",
		SubjectKeyID: "ab"})
	assert.NoError(t, err, "a certificate has a content filter")
	assert.Equal(t, "1", filter["serial_number"], "the serial number is part of the identity")
	assert.Equal(t, "printer.example.edu", filter["issuer_common_name"], "the issuer is part of the identity")
	assert.Equal(t, "ab", filter["subject_key_id"], "the key identifier is part of the identity")
	assert.Contains(t, filter, "authority_key_id", "the issuer's key identifier is part of the identity, empty or not")
}
