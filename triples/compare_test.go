// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package triples

import (
	"regexp"
	"testing"

	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/stretchr/testify/assert"
)

func TestNodeIsWildcard(t *testing.T) {
	// test that the method will fail when an attribute is specified with no type
	node, err := parseNode("<*,name:owasp.org>")
	assert.NoError(t, err, "Failed to parse the node element")
	assert.NotNil(t, node, "Parsed node element should not be nil")
	assert.False(t, node.IsWildcard(), "Expected failure when providing an attribute and no type")

	// test the conditions that should be considered a wildcard
	node, err = parseNode("<*>")
	assert.NoError(t, err, "Failed to parse the node element")
	assert.NotNil(t, node, "Parsed node element should not be nil")
	assert.True(t, node.IsWildcard(), "Expected success when nothing have been specified")

	node, err = parseNode("<fqdn:*>")
	assert.NoError(t, err, "Failed to parse the node element")
	assert.NotNil(t, node, "Parsed node element should not be nil")
	assert.True(t, node.IsWildcard(), "Expected success when only the node type is specified")

	node, err = parseNode("<fqdn:*, name:owasp.org>")
	assert.NoError(t, err, "Failed to parse the node element")
	assert.NotNil(t, node, "Parsed node element should not be nil")
	assert.True(t, node.IsWildcard(), "Expected success when a type and attribtue is specified")
}

func TestPredicateIsWildcard(t *testing.T) {
	// test that a predicate with a defined label is not considered a wildcard
	pred, err := parsePredicate("<*:dns_record>")
	assert.NoError(t, err, "Failed to parse the predicate element")
	assert.NotNil(t, pred, "Parsed predicate element should not be nil")
	assert.False(t, pred.IsWildcard(), "Expected failure when providing a predicate label")

	// test that the method will fail when an attribute is specified with no type
	pred, err = parsePredicate("<*,header.rr_type:1>")
	assert.NoError(t, err, "Failed to parse the predicate element")
	assert.NotNil(t, pred, "Parsed predicate element should not be nil")
	assert.False(t, pred.IsWildcard(), "Expected failure when providing an attribute and no type")

	// test that the method will fail when an attribute is specified with no type
	pred, err = parsePredicate("<*,header.rr_type:1>")
	assert.NoError(t, err, "Failed to parse the predicate element")
	assert.NotNil(t, pred, "Parsed predicate element should not be nil")
	assert.False(t, pred.IsWildcard(), "Expected failure when providing an attribute and no type")

	// test the conditions that should be considered a wildcard
	pred, err = parsePredicate("<*>")
	assert.NoError(t, err, "Failed to parse the predicate element")
	assert.NotNil(t, pred, "Parsed predicate element should not be nil")
	assert.True(t, pred.IsWildcard(), "Expected success when nothing have been specified")

	pred, err = parsePredicate("<simplerelation:*>")
	assert.NoError(t, err, "Failed to parse the predicate element")
	assert.NotNil(t, pred, "Parsed predicate element should not be nil")
	assert.True(t, pred.IsWildcard(), "Expected success when only the predicate type is specified")

	pred, err = parsePredicate("<basicdnsrelation:*, header.rr_type:1>")
	assert.NoError(t, err, "Failed to parse the predicate element")
	assert.NotNil(t, pred, "Parsed predicate element should not be nil")
	assert.True(t, pred.IsWildcard(), "Expected success when a type and attribtue is specified")
}

func TestIsRegexp(t *testing.T) {
	failstr := "#//#"
	str, ok := isRegexp(failstr)
	assert.False(t, ok, "Expected failure when the regexp is empty")
	assert.Equal(t, failstr, str, "Failure should return the input string")

	re := "anything"
	str, ok = isRegexp("#/" + re + "/#")
	assert.True(t, ok, "Expected success when the regexp is not empty")
	assert.Equal(t, re, str, "Success should return the trimmed input string")
}

func TestValueMatch(t *testing.T) {
	assert.False(t, valueMatch("test", "test1", nil), "Unequal values should return false")

	re := regexp.MustCompile("test.")
	assert.False(t, valueMatch("test", "", re), "Regexp not matching should result in false")
	assert.True(t, valueMatch("test", "TEST", nil), "Case insensitive matches should result in true")

	re = regexp.MustCompile("tes.*")
	assert.True(t, valueMatch("test", "", re), "A successful regexp match should return true")
}

func TestAllAttrsMatch(t *testing.T) {
	c := oamcert.TLSCertificate{
		SerialNumber:      "111222333444555",
		SubjectCommonName: "owasp.org",
	}

	assert.True(t, allAttrsMatch(c, nil), "Expected true when the slice of attributes is nil")

	attrs := map[string]*AttrValue{"subject_common_name": &AttrValue{Value: "owasp.org"}}
	assert.True(t, allAttrsMatch(c, attrs), "Expected true with a single matching value")

	attrs = map[string]*AttrValue{"subject_common_name": &AttrValue{Value: "owasp"}}
	assert.False(t, allAttrsMatch(c, attrs), "Expected false with a single value that doesn't match")

	attrs = map[string]*AttrValue{
		"serial_number":       &AttrValue{Value: "111222333444555"},
		"subject_common_name": &AttrValue{Value: "owasp.org"},
	}
	assert.True(t, allAttrsMatch(c, attrs), "Expected true with multiple matching values")

	attrs = map[string]*AttrValue{
		"serial_number":       &AttrValue{Value: "111222333444"},
		"subject_common_name": &AttrValue{Value: "owasp.org"},
	}
	assert.False(t, allAttrsMatch(c, attrs), "Expected false when one of multiple values doesn't match")

	attrs = map[string]*AttrValue{
		"serial_number":       &AttrValue{Regexp: regexp.MustCompile("111222333444.*")},
		"subject_common_name": &AttrValue{Value: "owasp.org"},
	}
	assert.True(t, allAttrsMatch(c, attrs), "Expected true with multiple matching values and regular expressions")

	attrs = map[string]*AttrValue{
		"serial_number":       &AttrValue{Regexp: regexp.MustCompile("^222333444.*")},
		"subject_common_name": &AttrValue{Value: "owasp.org"},
	}
	assert.False(t, allAttrsMatch(c, attrs), "Expected flase when a regular expression doesn't match")
}

func TestAttrMatch(t *testing.T) {
	acct := &oamacct.Account{
		Username: "caffix",
		Balance:  50.0,
		Active:   true,
	}

	assert.False(t, attrMatch(acct, "invalid", &AttrValue{Value: "true"}), "invalid field names should return false")
	// test that boolean values can be compared
	assert.True(t, attrMatch(acct, "active", &AttrValue{Value: "true"}), "Expected true when boolean values match")
	assert.False(t, attrMatch(acct, "active", &AttrValue{Value: "invalid"}), "Expected false when boolean value do not match")
	// test that string values can be compared
	assert.True(t, attrMatch(acct, "username", &AttrValue{Value: "caffix"}), "Expected true when string values match")
	assert.False(t, attrMatch(acct, "username", &AttrValue{Value: "other handle"}), "Expected false when string values do not match")
	// test that float values can be compared
	assert.True(t, attrMatch(acct, "balance", &AttrValue{Value: "50"}), "Expected true when float values match")
	assert.False(t, attrMatch(acct, "balance", &AttrValue{Value: "50.5"}), "Expected false when float values do not match")

	bdr := &oamdns.BasicDNSRelation{
		Name: "dns_record",
		Header: oamdns.RRHeader{
			RRType: 1,
			Class:  1,
			TTL:    3600,
		},
	}
	assert.False(t, attrMatch(bdr, "header.invalid", &AttrValue{Value: "1"}), "Invalid field name in valid struct should return false")
	// test that int values can be compared
	assert.True(t, attrMatch(bdr, "header.rr_type", &AttrValue{Value: "1"}), "Expected true when int values match")
	assert.False(t, attrMatch(bdr, "header.rr_type", &AttrValue{Value: "2"}), "Expected false when int values do not match")
}
