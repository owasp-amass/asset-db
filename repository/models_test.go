// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/glebarez/sqlite"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/fingerprint"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	"github.com/owasp-amass/open-asset-model/source"
	oamtls "github.com/owasp-amass/open-asset-model/tls_certificate"
	"github.com/owasp-amass/open-asset-model/url"
	"github.com/owasp-amass/open-asset-model/whois"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func TestModels(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.1")
	cidr := netip.MustParsePrefix("198.51.100.0/24")

	t.Run("Parse", func(t *testing.T) {
		testCases := []struct {
			description string
			asset       oam.Asset
		}{
			{
				description: "parse fqdn",
				asset:       &domain.FQDN{Name: "www.example.com"},
			},
			{
				description: "parse ip address",
				asset:       &network.IPAddress{Address: ip, Type: "IPv4"},
			},
			{
				description: "parse netblock",
				asset:       &network.Netblock{Cidr: cidr, Type: "IPv4"},
			},
			{
				description: "parse rir oganization",
				asset:       &network.RIROrganization{Name: "Google LLC", RIRId: "GOGL", RIR: "ARIN"},
			},
			{
				description: "parse asn",
				asset:       &network.AutonomousSystem{Number: 64496},
			},
			{
				description: "parse domain record",
				asset:       &whois.DomainRecord{Domain: "example.com"},
			},
			{
				description: "parse url",
				asset:       &url.URL{Raw: "https://www.example.com"},
			},
			{
				description: "parse tls certificate",
				asset:       &oamtls.TLSCertificate{SerialNumber: "25:89:5f:3b:96:c8:18:89:09:04:8b:6c:64:88:6f:1b"},
			},
			{
				description: "parse socket address",
				asset:       &network.SocketAddress{Address: netip.MustParseAddrPort("192.168.1.1:443")},
			},
			{
				description: "parse person",
				asset:       &people.Person{FullName: "John Doe"},
			},
			{
				description: "parse phone",
				asset:       &contact.Phone{Raw: "+1-202-555-0104"},
			},
			{
				description: "parse email",
				asset:       &contact.EmailAddress{Address: "test@example.com"},
			},
			{
				description: "parse location",
				asset:       &contact.Location{Address: "1600 Pennsylvania Ave NW, Washington, DC 20500"},
			},
			{
				description: "parse fingerprint",
				asset:       &fingerprint.Fingerprint{Value: "a1:2b:3c:4d:5e:6f:7g:8h:9i:0j:1k:2l:3m:4n:5o:6p"},
			},
			{
				description: "parse registrar",
				asset:       &whois.Registrar{Name: "Registrar, Inc."},
			},
			{
				description: "parse organization",
				asset:       &org.Organization{Name: "Example, Inc."},
			},
			{
				description: "parse contact record",
				asset:       &contact.ContactRecord{DiscoveredAt: "https://owasp.org"},
			},
			{
				description: "parse source",
				asset:       &source.Source{Name: "https://www.owasp.org"},
			},
		}

		for _, tc := range testCases {
			jsonContent, err := tc.asset.JSON()
			if err != nil {
				t.Fatalf("failed to marshal asset: %s", err)
			}

			asset := &Asset{
				Type:    string(tc.asset.AssetType()),
				Content: jsonContent,
			}

			parsedAsset, err := asset.Parse()
			if err != nil {
				t.Fatalf("failed to parse asset: %s", err)
			}

			if !reflect.DeepEqual(parsedAsset, tc.asset) {
				t.Fatalf("expected asset %v, got %v", tc.asset, parsedAsset)
			}
		}
	})

	t.Run("JSONQuery", func(t *testing.T) {
		testCases := []struct {
			description   string
			asset         oam.Asset
			expectedQuery *datatypes.JSONQueryExpression
		}{
			{
				description:   "json query for fqdn",
				asset:         &domain.FQDN{Name: "www.example.com"},
				expectedQuery: datatypes.JSONQuery("content").Equals("www.example.com", "name"),
			},
			{
				description:   "json query for ip address",
				asset:         &network.IPAddress{Address: ip, Type: "IPv4"},
				expectedQuery: datatypes.JSONQuery("content").Equals(ip, "address"),
			},
			{
				description:   "json query for netblock",
				asset:         &network.Netblock{Cidr: cidr, Type: "IPv4"},
				expectedQuery: datatypes.JSONQuery("content").Equals(cidr, "cidr"),
			},
			{
				description:   "json query for rir oganization",
				asset:         &network.RIROrganization{Name: "Google LLC", RIRId: "GOGL", RIR: "ARIN"},
				expectedQuery: datatypes.JSONQuery("content").Equals("Google LLC", "name"),
			},
			{
				description:   "json query for asn",
				asset:         &network.AutonomousSystem{Number: 64496},
				expectedQuery: datatypes.JSONQuery("content").Equals(64496, "number"),
			},
			{
				description:   "json query for socket address",
				asset:         &network.SocketAddress{Address: netip.MustParseAddrPort("192.168.1.1:443")},
				expectedQuery: datatypes.JSONQuery("content").Equals("192.168.1.1:443", "address"),
			},
			{
				description:   "json query for person",
				asset:         &people.Person{FullName: "John Doe"},
				expectedQuery: datatypes.JSONQuery("content").Equals("John Doe", "full_name"),
			},
			{
				description:   "json query for phone",
				asset:         &contact.Phone{Raw: "+1-202-555-0104"},
				expectedQuery: datatypes.JSONQuery("content").Equals("+1-202-555-0104", "raw"),
			},
			{
				description:   "json query for email",
				asset:         &contact.EmailAddress{Address: "test@example.com"},
				expectedQuery: datatypes.JSONQuery("content").Equals("test@example.com", "address"),
			},
			{
				description:   "json query for location",
				asset:         &contact.Location{Address: "1600 Pennsylvania Ave NW, Washington, DC 20500"},
				expectedQuery: datatypes.JSONQuery("content").Equals("1600 Pennsylvania Ave NW, Washington, DC 20500", "address"),
			},
			{
				description:   "json query for fingerprint",
				asset:         &fingerprint.Fingerprint{Value: "a1:2b:3c:4d:5e:6f:7g:8h:9i:0j:1k:2l:3m:4n:5o:6p"},
				expectedQuery: datatypes.JSONQuery("content").Equals("a1:2b:3c:4d:5e:6f:7g:8h:9i:0j:1k:2l:3m:4n:5o:6p", "value"),
			},
			{
				description:   "json query for url",
				asset:         &url.URL{Raw: "https://www.example.com"},
				expectedQuery: datatypes.JSONQuery("content").Equals("https://www.example.com", "url"),
			},
			{
				description:   "json query for tls certificate",
				asset:         &oamtls.TLSCertificate{SerialNumber: "25:89:5f:3b:96:c8:18:89:09:04:8b:6c:64:88:6f:1b"},
				expectedQuery: datatypes.JSONQuery("content").Equals("25:89:5f:3b:96:c8:18:89:09:04:8b:6c:64:88:6f:1b", "serial_number"),
			},
			{
				description:   "json query for whois",
				asset:         &whois.DomainRecord{Domain: "example.com"},
				expectedQuery: datatypes.JSONQuery("content").Equals("example.com", "domain"),
			},
			{
				description:   "json query for registrar",
				asset:         &whois.Registrar{Name: "Registrar, Inc."},
				expectedQuery: datatypes.JSONQuery("content").Equals("Registrar, Inc.", "name"),
			},
			{
				description:   "json query for organization",
				asset:         &org.Organization{Name: "Example, Inc."},
				expectedQuery: datatypes.JSONQuery("content").Equals("Example, Inc.", "name"),
			},
			{
				description:   "json query for contact record",
				asset:         &contact.ContactRecord{DiscoveredAt: "https://owasp.org"},
				expectedQuery: datatypes.JSONQuery("content").Equals("https://owasp.org", "discovered_at"),
			},
			{
				description:   "json query for source",
				asset:         &source.Source{Name: "https://www.owasp.org"},
				expectedQuery: datatypes.JSONQuery("content").Equals("https://www.owasp.org", "name"),
			},
		}

		for _, tc := range testCases {
			jsonContent, err := tc.asset.JSON()
			if err != nil {
				t.Fatalf("failed to marshal asset: %s", err)
			}

			asset := &Asset{
				Type:    string(tc.asset.AssetType()),
				Content: jsonContent,
			}

			jsonQuery, err := asset.JSONQuery()
			if err != nil {
				t.Fatalf("failed to generate json query: %s", err)
			}

			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatalf("failed to open db: %s", err)
			}

			sqlQuery := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
				return tx.Where(jsonQuery).First(asset)
			})

			expectedSqlQuery := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
				return tx.Where(tc.expectedQuery).First(asset)
			})

			if sqlQuery != expectedSqlQuery {
				t.Fatalf("expected sql query %s, got %s", expectedSqlQuery, sqlQuery)
			}
		}
	})
}
