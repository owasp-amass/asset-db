package repository_test

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/glebarez/sqlite"
	. "github.com/owasp-amass/asset-db/repository"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/fingerprint"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	oamtls "github.com/owasp-amass/open-asset-model/tls_certificates"
	"github.com/owasp-amass/open-asset-model/url"
	"github.com/owasp-amass/open-asset-model/whois"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func TestModels(t *testing.T) {
	ip, _ := netip.ParseAddr("192.168.1.1")
	cidr, _ := netip.ParsePrefix("198.51.100.0/24")

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
				description: "parse whois",
				asset:       &whois.WHOIS{Domain: "example.com"},
			},
			{
				description: "parse url",
				asset:       &url.URL{Raw: "https://www.example.com"},
			},
			{
				description: "parse tls certificate",
				asset:       &oamtls.TLSCertificate{CommonName: "www.example.com"},
			},
			{
				description: "parse port",
				asset:       &network.Port{Number: 443},
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
				asset:       &contact.Location{FormattedAddress: "1600 Pennsylvania Ave NW, Washington, DC 20500"},
			},
			{
				description: "parse fingerprint",
				asset:       &fingerprint.Fingerprint{String: "a1:2b:3c:4d:5e:6f:7g:8h:9i:0j:1k:2l:3m:4n:5o:6p"},
			},
			{
				description: "parse registrar",
				asset:       &whois.Registrar{Name: "Registrar, Inc."},
			},
			{
				description: "parse organization",
				asset:       &org.Organization{OrgName: "Example, Inc."},
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
				description:   "json query for port",
				asset:         &network.Port{Number: 443},
				expectedQuery: datatypes.JSONQuery("content").Equals(443, "number"),
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
				asset:         &contact.Location{FormattedAddress: "1600 Pennsylvania Ave NW, Washington, DC 20500"},
				expectedQuery: datatypes.JSONQuery("content").Equals("1600 Pennsylvania Ave NW, Washington, DC 20500", "formatted_address"),
			},
			{
				description:   "json query for fingerprint",
				asset:         &fingerprint.Fingerprint{String: "a1:2b:3c:4d:5e:6f:7g:8h:9i:0j:1k:2l:3m:4n:5o:6p"},
				expectedQuery: datatypes.JSONQuery("content").Equals("a1:2b:3c:4d:5e:6f:7g:8h:9i:0j:1k:2l:3m:4n:5o:6p", "string"),
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
				asset:         &whois.WHOIS{Domain: "example.com"},
				expectedQuery: datatypes.JSONQuery("content").Equals("example.com", "domain"),
			},
			{
				description:   "json query for registrar",
				asset:         &whois.Registrar{Name: "Registrar, Inc."},
				expectedQuery: datatypes.JSONQuery("content").Equals("Registrar, Inc.", "name"),
			},
			{
				description:   "json query for organization",
				asset:         &org.Organization{OrgName: "Example, Inc."},
				expectedQuery: datatypes.JSONQuery("content").Equals("Example, Inc.", "org_name"),
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
