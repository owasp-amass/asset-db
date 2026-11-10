// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"strings"
	"testing"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
)

func TestTagValueQueryUsesParameters(t *testing.T) {
	value := "google-site-verification=abc' RETURN 1 //"
	query, params, err := tagValueQuery(oam.FQDN, "dns_record", value, false, time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(query, "abc") || params["value"] != value || params["name"] != "dns_record" ||
		params["limit"] != 11 {
		t.Errorf("query %q with params %v", query, params)
	}
	if !strings.Contains(query, "(a:Entity:FQDN {entity_id: eid})") ||
		!strings.Contains(query, "coalesce(p.property_value, p.data) = $value") {
		t.Errorf("query = %q", query)
	}

	query, params, err = tagValueQuery(oam.FQDN, "dns_record", "Example.COM", true, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if params["value"] != "example.com" || params["since"] == nil || !strings.Contains(query, "CONTAINS $value") ||
		!strings.Contains(query, "p.updated_at >= $since") {
		t.Errorf("contains query %q with params %v", query, params)
	}
}

func TestAttributeQueryUsesParameters(t *testing.T) {
	query, params, err := attributeQuery(oam.TLSCertificate, "subject_key_id", "aa:bb", time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if query != "MATCH (a:Entity:TLSCertificate) WHERE a[$key] = $value RETURN a ORDER BY a.entity_id LIMIT $limit" ||
		params["key"] != "subject_key_id" || params["value"] != "aa:bb" || params["limit"] != 6 {
		t.Errorf("query %q with params %v", query, params)
	}
}

func TestValueQueriesRejectUnsafeInput(t *testing.T) {
	if _, _, err := tagValueQuery(oam.AssetType("FQDN) DETACH DELETE (x"), "dns_record", "v", false,
		time.Time{}, 10); err == nil {
		t.Error("an asset type outside OAM was accepted as a label")
	}
	if _, _, err := attributeQuery(oam.TLSCertificate, "subject_key_id] = 1 OR a[x", "v", time.Time{}, 10); err == nil {
		t.Error("an attribute key that is not an identifier was accepted")
	}
	if _, _, err := tagValueQuery(oam.FQDN, "dns_record", "v", false, time.Time{}, 501); err == nil {
		t.Error("a limit above 500 was accepted")
	}
}
