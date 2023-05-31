package repository_test

import (
	"net/netip"
	"testing"

	. "github.com/owasp-amass/asset-db/repository"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"

	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
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
				asset:       domain.FQDN{Name: "www.example.com"},
			},
			{
				description: "parse ip address",
				asset:       network.IPAddress{Address: ip, Type: "IPv4"},
			},
			{
				description: "parse netblock",
				asset:       network.Netblock{Cidr: cidr, Type: "IPv4"},
			},
			{
				description: "parse rir oganization",
				asset:       network.RIROrganization{Name: "Google LLC", RIRId: "GOGL", RIR: "ARIN"},
			},
			{
				description: "parse asn",
				asset:       network.AutonomousSystem{Number: 64496},
			},
		}

		for _, tc := range testCases {
			jsonContent, err := tc.asset.JSON()
			if err != nil {
				t.Fatalf("failed to marshal asset: %s", err)
			}

			asset := Asset{
				Type:    string(tc.asset.AssetType()),
				Content: jsonContent,
			}

			parsedAsset, err := asset.Parse()
			if err != nil {
				t.Fatalf("failed to parse asset: %s", err)
			}

			if parsedAsset != tc.asset {
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
				asset:         domain.FQDN{Name: "www.example.com"},
				expectedQuery: datatypes.JSONQuery("content").Equals("www.example.com", "name"),
			},
			{
				description:   "json query for ip address",
				asset:         network.IPAddress{Address: ip, Type: "IPv4"},
				expectedQuery: datatypes.JSONQuery("content").Equals(ip, "address"),
			},
			{
				description:   "json query for netblock",
				asset:         network.Netblock{Cidr: cidr, Type: "IPv4"},
				expectedQuery: datatypes.JSONQuery("content").Equals(cidr, "cidr"),
			},
			{
				description:   "json query for rir oganization",
				asset:         network.RIROrganization{Name: "Google LLC", RIRId: "GOGL", RIR: "ARIN"},
				expectedQuery: datatypes.JSONQuery("content").Equals("Google LLC", "name"),
			},
			{
				description:   "json query for asn",
				asset:         network.AutonomousSystem{Number: 64496},
				expectedQuery: datatypes.JSONQuery("content").Equals(64496, "number"),
			},
		}

		for _, tc := range testCases {
			jsonContent, err := tc.asset.JSON()
			if err != nil {
				t.Fatalf("failed to marshal asset: %s", err)
			}

			asset := Asset{
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
				return tx.Where(jsonQuery).First(&asset)
			})

			expectedSqlQuery := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
				return tx.Where(tc.expectedQuery).First(&asset)
			})

			if sqlQuery != expectedSqlQuery {
				t.Fatalf("expected sql query %s, got %s", expectedSqlQuery, sqlQuery)
			}
		}
	})
}
