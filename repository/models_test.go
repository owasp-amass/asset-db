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
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/service"
	"github.com/owasp-amass/open-asset-model/url"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func TestModels(t *testing.T) {
	nethandle := "NET-198-51-100-0-1"
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
				description: "parse ip network record",
				asset:       &oamreg.IPNetRecord{CIDR: cidr, Type: "IPv4", Handle: nethandle},
			},
			{
				description: "parse netblock",
				asset:       &network.Netblock{CIDR: cidr, Type: "IPv4"},
			},
			{
				description: "parse autnum record",
				asset:       &oamreg.AutnumRecord{Number: 64496, Handle: "AS64496"},
			},
			{
				description: "parse asn",
				asset:       &network.AutonomousSystem{Number: 64496},
			},
			{
				description: "parse domain record",
				asset:       &oamreg.DomainRecord{Domain: "example.com"},
			},
			{
				description: "parse url",
				asset:       &url.URL{Raw: "https://www.example.com"},
			},
			{
				description: "parse tls certificate",
				asset:       &oamcert.TLSCertificate{SerialNumber: "25:89:5f:3b:96:c8:18:89:09:04:8b:6c:64:88:6f:1b"},
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
				description: "parse organization",
				asset:       &org.Organization{Name: "Example, Inc."},
			},
			{
				description: "parse contact record",
				asset:       &contact.ContactRecord{DiscoveredAt: "https://owasp.org"},
			},
			{
				description: "parse service",
				asset:       &service.Service{Identifier: "12345"},
			},
		}

		for _, tc := range testCases {
			jsonContent, err := tc.asset.JSON()
			if err != nil {
				t.Fatalf("failed to marshal asset: %s", err)
			}

			entity := &Entity{
				Type:    string(tc.asset.AssetType()),
				Content: jsonContent,
			}

			parsedEntity, err := entity.Parse()
			if err != nil {
				t.Fatalf("failed to parse asset: %s", err)
			}

			if !reflect.DeepEqual(parsedEntity, tc.asset) {
				t.Fatalf("expected asset %v, got %v", tc.asset, parsedEntity)
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
				description:   "json query for ip network record",
				asset:         &oamreg.IPNetRecord{CIDR: cidr, Type: "IPv4", Handle: nethandle},
				expectedQuery: datatypes.JSONQuery("content").Equals(nethandle, "handle"),
			},
			{
				description:   "json query for netblock",
				asset:         &network.Netblock{CIDR: cidr, Type: "IPv4"},
				expectedQuery: datatypes.JSONQuery("content").Equals(cidr, "cidr"),
			},
			{
				description:   "json query for autnum record",
				asset:         &oamreg.AutnumRecord{Number: 26808, Handle: "AS26808"},
				expectedQuery: datatypes.JSONQuery("content").Equals("AS26808", "handle"),
			},
			{
				description:   "json query for asn",
				asset:         &network.AutonomousSystem{Number: 64496},
				expectedQuery: datatypes.JSONQuery("content").Equals(64496, "number"),
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
				description:   "json query for url",
				asset:         &url.URL{Raw: "https://www.example.com"},
				expectedQuery: datatypes.JSONQuery("content").Equals("https://www.example.com", "url"),
			},
			{
				description:   "json query for tls certificate",
				asset:         &oamcert.TLSCertificate{SerialNumber: "25:89:5f:3b:96:c8:18:89:09:04:8b:6c:64:88:6f:1b"},
				expectedQuery: datatypes.JSONQuery("content").Equals("25:89:5f:3b:96:c8:18:89:09:04:8b:6c:64:88:6f:1b", "serial_number"),
			},
			{
				description:   "json query for the domain record",
				asset:         &oamreg.DomainRecord{Domain: "example.com"},
				expectedQuery: datatypes.JSONQuery("content").Equals("example.com", "domain"),
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
				description:   "json query for service",
				asset:         &service.Service{Identifier: "12345"},
				expectedQuery: datatypes.JSONQuery("content").Equals("12345", "identifier"),
			},
		}

		for _, tc := range testCases {
			jsonContent, err := tc.asset.JSON()
			if err != nil {
				t.Fatalf("failed to marshal asset: %s", err)
			}

			entity := &Entity{
				Type:    string(tc.asset.AssetType()),
				Content: jsonContent,
			}

			jsonQuery, err := entity.JSONQuery()
			if err != nil {
				t.Fatalf("failed to generate json query: %s", err)
			}

			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatalf("failed to open db: %s", err)
			}

			sqlQuery := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
				return tx.Where(jsonQuery).First(entity)
			})

			expectedSqlQuery := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
				return tx.Where(tc.expectedQuery).First(entity)
			})

			if sqlQuery != expectedSqlQuery {
				t.Fatalf("expected sql query %s, got %s", expectedSqlQuery, sqlQuery)
			}
		}
	})
}
