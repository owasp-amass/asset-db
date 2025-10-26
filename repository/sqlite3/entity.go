// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// Entity models a row in `entities` plus its inlined concrete Asset.
// Attrs is raw JSON from entities.attrs (may be nil/"{}").
type Entity struct {
	EntityID     int64           `json:"entity_id"`
	Type         string          `json:"type"`          // entity_type_lu.name
	DisplayValue string          `json:"display_value"` // entities.display_value (normalized for some types)
	Attrs        json.RawMessage `json:"attrs"`         // entities.attrs
	Asset        any             `json:"asset"`         // concrete asset struct
}

func (r *sqliteRepository) CreateEntity(ctx context.Context, entity *types.Entity) (*types.Entity, error) {
	return r.CreateAsset(ctx, entity.Asset)
}

func (r *sqliteRepository) CreateAsset(ctx context.Context, asset oam.Asset) (*types.Entity, error) {
	var eid int64
	var err error

	switch asset.AssetType() {
	case oam.Account:
		eid, err = r.stmts.UpsertAccount(ctx, asset.(*oamacct.Account))
	case oam.AutnumRecord:
		eid, err = r.stmts.UpsertAutnumRecord(ctx, asset.(*oamreg.AutnumRecord))
	case oam.AutonomousSystem:
		eid, err = r.stmts.UpsertAutonomousSystem(ctx, asset.(*oamnet.AutonomousSystem))
	case oam.ContactRecord:
		eid, err = r.stmts.UpsertContactRecord(ctx, asset.(*contact.ContactRecord))
	case oam.DomainRecord:
		eid, err = r.stmts.UpsertDomainRecord(ctx, asset.(*oamreg.DomainRecord))
	case oam.File:
		eid, err = r.stmts.UpsertFile(ctx, asset.(*oamfile.File))
	case oam.FQDN:
		eid, err = r.stmts.UpsertFQDN(ctx, asset.(*oamdns.FQDN))
	case oam.FundsTransfer:
		eid, err = r.stmts.UpsertFundsTransfer(ctx, asset.(*oamfin.FundsTransfer))
	case oam.Identifier:
		eid, err = r.stmts.UpsertIdentifier(ctx, asset.(*oamgen.Identifier))
	case oam.IPAddress:
		eid, err = r.stmts.UpsertIPAddress(ctx, asset.(*oamnet.IPAddress))
	case oam.IPNetRecord:
		eid, err = r.stmts.UpsertIPNetRecord(ctx, asset.(*oamreg.IPNetRecord))
	case oam.Location:
		eid, err = r.stmts.UpsertLocation(ctx, asset.(*contact.Location))
	case oam.Netblock:
		eid, err = r.stmts.UpsertNetblock(ctx, asset.(*oamnet.Netblock))
	case oam.Organization:
		eid, err = r.stmts.UpsertOrganization(ctx, asset.(*oamorg.Organization))
	case oam.Person:
		eid, err = r.stmts.UpsertPerson(ctx, asset.(*people.Person))
	case oam.Phone:
		eid, err = r.stmts.UpsertPhone(ctx, asset.(*contact.Phone))
	case oam.Product:
		eid, err = r.stmts.UpsertProduct(ctx, asset.(*oamplat.Product))
	case oam.ProductRelease:
		eid, err = r.stmts.UpsertProductRelease(ctx, asset.(*oamplat.ProductRelease))
	case oam.Service:
		eid, err = r.stmts.UpsertService(ctx, asset.(*oamplat.Service))
	case oam.TLSCertificate:
		eid, err = r.stmts.UpsertTLSCertificate(ctx, asset.(*oamcert.TLSCertificate))
	case oam.URL:
		eid, err = r.stmts.UpsertURL(ctx, asset.(*oamurl.URL))
	default:
		return nil, fmt.Errorf("unsupported asset type %q", asset.AssetType())
	}

	if err != nil {
		return nil, err
	}
	return r.queries.FindEntityByID(ctx, eid)
}

// ============================== Registry ==============================

// regEntry describes what content keys are allowed for each table and how
// they map to columns + normalization.
type regEntry struct {
	// keys is a stable slice of allowed external filter keys (e.g., "fqdn", "domain", "ip_address")
	keys []string
	// colMap maps external key -> actual column expression (e.g., "fqdn" -> "lower(a.fqdn)")
	colMap map[string]string
}

// contentRegistry: per-table filters you can search on.
// Feel free to expand with more columns if needed.
var contentRegistry = map[string]regEntry{
	"fqdn": {
		keys: []string{"fqdn"},
		colMap: map[string]string{
			"fqdn": "lower(a.fqdn)",
		},
	},
	"ipaddress": {
		keys: []string{"ip_address", "ip_version"},
		colMap: map[string]string{
			"ip_address": "a.ip_address",
			"ip_version": "a.ip_version",
		},
	},
	"domainrecord": {
		keys: []string{"domain", "record_name", "extension", "punycode"},
		colMap: map[string]string{
			"domain":      "lower(a.domain)",
			"record_name": "lower(a.record_name)",
			"extension":   "a.extension",
			"punycode":    "a.punycode",
		},
	},
	"url": {
		keys: []string{"raw_url", "host", "url_path", "port", "scheme"},
		colMap: map[string]string{
			"raw_url":  "a.raw_url",
			"host":     "a.host",
			"url_path": "a.url_path",
			"port":     "a.port",
			"scheme":   "a.scheme",
		},
	},
	"organization": {
		keys: []string{"unique_id", "legal_name", "org_name"},
		colMap: map[string]string{
			"unique_id":  "a.unique_id",
			"legal_name": "a.legal_name",
			"org_name":   "a.org_name",
		},
	},
	"autonomoussystem": {
		keys: []string{"asn"},
		colMap: map[string]string{
			"asn": "a.asn",
		},
	},
	"autnumrecord": {
		keys: []string{"asn", "handle", "record_name"},
		colMap: map[string]string{
			"asn":         "a.asn",
			"handle":      "a.handle",
			"record_name": "a.record_name",
		},
	},
	"ipnetrecord": {
		keys: []string{"record_cidr", "handle", "ip_version", "country"},
		colMap: map[string]string{
			"record_cidr": "a.record_cidr",
			"handle":      "a.handle",
			"ip_version":  "a.ip_version",
			"country":     "a.country",
		},
	},
	"netblock": {
		keys: []string{"netblock_cidr", "ip_version"},
		colMap: map[string]string{
			"netblock_cidr": "a.netblock_cidr",
			"ip_version":    "a.ip_version",
		},
	},
	"file": {
		keys: []string{"file_url", "basename", "file_type"},
		colMap: map[string]string{
			"file_url":  "a.file_url",
			"basename":  "a.basename",
			"file_type": "a.file_type",
		},
	},
	"service": {
		keys: []string{"unique_id", "service_type"},
		colMap: map[string]string{
			"unique_id":    "a.unique_id",
			"service_type": "a.service_type",
		},
	},
	"identifier": {
		keys: []string{"unique_id", "id_type"},
		colMap: map[string]string{
			"unique_id": "a.unique_id",
			"id_type":   "a.id_type",
		},
	},
	"account": {
		keys: []string{"unique_id", "account_type", "username", "account_number"},
		colMap: map[string]string{
			"unique_id":      "a.unique_id",
			"account_type":   "a.account_type",
			"username":       "a.username",
			"account_number": "a.account_number",
		},
	},
	"fundstransfer": {
		keys: []string{"unique_id", "reference_number", "currency", "transfer_method"},
		colMap: map[string]string{
			"unique_id":        "a.unique_id",
			"reference_number": "a.reference_number",
			"currency":         "a.currency",
			"transfer_method":  "a.transfer_method",
		},
	},
	"location": {
		keys: []string{"street_address", "city", "country", "postal_code"},
		colMap: map[string]string{
			"street_address": "a.street_address",
			"city":           "a.city",
			"country":        "a.country",
			"postal_code":    "a.postal_code",
		},
	},
	"person": {
		keys: []string{"unique_id", "full_name", "first_name", "family_name"},
		colMap: map[string]string{
			"unique_id":   "a.unique_id",
			"full_name":   "a.full_name",
			"first_name":  "a.first_name",
			"family_name": "a.family_name",
		},
	},
	"phone": {
		keys: []string{"e164", "raw_number", "country_abbrev"},
		colMap: map[string]string{
			"e164":           "a.e164",
			"raw_number":     "a.raw_number",
			"country_abbrev": "a.country_abbrev",
		},
	},
	"product": {
		keys: []string{"unique_id", "product_name", "product_type", "category"},
		colMap: map[string]string{
			"unique_id":    "a.unique_id",
			"product_name": "a.product_name",
			"product_type": "a.product_type",
			"category":     "a.category",
		},
	},
	"productrelease": {
		keys: []string{"release_name"},
		colMap: map[string]string{
			"release_name": "a.release_name",
		},
	},
	"tlscertificate": {
		keys: []string{"serial_number", "subject_common_name", "issuer_common_name"},
		colMap: map[string]string{
			"serial_number":       "a.serial_number",
			"subject_common_name": "a.subject_common_name",
			"issuer_common_name":  "a.issuer_common_name",
		},
	},
}

// buildWhere validates the provided filters and builds "col = ?" AND ... with args.
// It honors case-insensitive matching for columns that already use lower() in colMap.
func buildWhere(table string, reg regEntry, filters ContentFilters) (string, []any, error) {
	if len(filters) == 0 {
		// No filters — allow full scan over that table via entity_ref (but still ordered by updated_at).
		// Usually caller should set a LIMIT in this case.
		return "", nil, nil
	}
	// Validate keys and order them stably for deterministic SQL key (cache)
	allowed := map[string]struct{}{}
	for _, k := range reg.keys {
		allowed[k] = struct{}{}
	}
	keys := slices.Sorted(maps.Keys(filters))

	parts := make([]string, 0, len(keys))
	args := make([]any, 0, len(keys))
	for _, k := range keys {
		if _, ok := allowed[k]; !ok {
			return "", nil, fmt.Errorf("unsupported filter %q for table %s (allowed: %v)", k, table, reg.keys)
		}
		col := reg.colMap[k]
		if col == "" {
			return "", nil, fmt.Errorf("no column mapping for filter %q on table %s", k, table)
		}
		// For lower(a.col) use normalized string value if possible
		val := filters[k]
		if strings.HasPrefix(col, "lower(") {
			if s, ok := val.(string); ok {
				val = strings.ToLower(s)
			}
		}
		parts = append(parts, col+" = ?")
		args = append(args, val)
	}
	return strings.Join(parts, " AND "), args, nil
}

// ============================== Asset hydration ==============================

func normalizeTable(name string) string { return strings.ToLower(strings.TrimSpace(name)) }
func normalizeType(name string) string  { return strings.ToLower(strings.TrimSpace(name)) }

// normalizeValueForType applies display_value normalization the same way
// your ingestion does (lowercase for fqdn/domainrecord; others exact).
func normalizeValueForType(t, v string) string {
	switch t {
	case "fqdn", "domainrecord":
		return strings.ToLower(v)
	default:
		return v
	}
}

// validateAssetTable ensures we only allow deletion against known asset tables.
// Returns normalized table name or "" if unsupported.
func validateAssetTable(tableName string) string {
	switch strings.ToLower(strings.TrimSpace(tableName)) {
	case "account",
		"autnumrecord",
		"autonomoussystem",
		"contactrecord",
		"domainrecord",
		"file",
		"fqdn",
		"fundstransfer",
		"identifier",
		"ipaddress",
		"ipnetrecord",
		"location",
		"netblock",
		"organization",
		"person",
		"phone",
		"product",
		"productrelease",
		"service",
		"tlscertificate",
		"url":
		return strings.ToLower(strings.TrimSpace(tableName))
	default:
		return ""
	}
}

func (r *Queries) loadEntityCore(ctx context.Context, entityID int64) (*Entity, error) {
	var e Entity
	var raw string
	if err := r.stmtEntityByID.QueryRowContext(ctx, entityID).Scan(&e.EntityID, &e.Type, &e.DisplayValue, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("entity %d not found", entityID)
		}
		return nil, err
	}
	if strings.TrimSpace(raw) != "" {
		e.Attrs = json.RawMessage(raw)
	}
	return &e, nil
}

func (r *Queries) fetchCompleteRepoEntity(ctx context.Context, e *Entity) (*types.Entity, error) {
	table := e.Type
	if table == "" {
		return nil, fmt.Errorf("no table mapping for entity type %q", e.Type)
	}
	// Resolve the row id in that concrete table via entity_ref
	var rowID int64
	if err := r.stmtRefRowByEntityTable.QueryRowContext(ctx, e.EntityID, table).Scan(&rowID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Entity exists but does not have a ref to the expected table (data drift)
			return nil, fmt.Errorf("entity %d has no %s row mapping", e.EntityID, table)
		}
		return nil, err
	}

	return r.fetchEntityAssetByTableID(ctx, e.EntityID, table, rowID)
}

// fetchEntityAssetByTableID selects the concrete asset row and scans into its struct.
// Statements are prepared lazily and cached per table name.
func (r *Queries) fetchEntityAssetByTableID(ctx context.Context, entity_id int64, table string, id int64) (*types.Entity, error) {
	switch table {
	case "account":
		return r.fetchAccountByRowID(ctx, entity_id, id)
	case "autnumrecord":
		return r.fetchAutnumRecordByRowID(ctx, entity_id, id)
	case "autonomoussystem":
		return r.fetchAutonomousSystemByRowID(ctx, entity_id, id)
	case "contactrecord":
		return r.fetchContactRecordByRowID(ctx, entity_id, id)
	case "domainrecord":
		return r.fetchDomainRecordByRowID(ctx, entity_id, id)
	case "file":
		return r.fetchFileByRowID(ctx, entity_id, id)
	case "fqdn":
		return r.fetchFQDNByRowID(ctx, entity_id, id)
	case "fundstransfer":
		return r.fetchFundsTransferByRowID(ctx, entity_id, id)
	case "identifier":
		return r.fetchIdentifierByRowID(ctx, entity_id, id)
	case "ipaddress":
		return r.fetchIPAddressByRowID(ctx, entity_id, id)
	case "ipnetrecord":
		return r.fetchIPNetRecordByRowID(ctx, entity_id, id)
	case "location":
		return r.fetchLocationByRowID(ctx, entity_id, id)
	case "netblock":
		return r.fetchNetblockByRowID(ctx, entity_id, id)
	case "organization":
		return r.fetchOrganizationByRowID(ctx, entity_id, id)
	case "person":
		return r.fetchPersonByRowID(ctx, entity_id, id)
	case "phone":
		return r.fetchPhoneByRowID(ctx, entity_id, id)
	case "product":
		return r.fetchProductByRowID(ctx, entity_id, id)
	case "productrelease":
		return r.fetchProductReleaseByRowID(ctx, entity_id, id)
	case "service":
		return r.fetchServiceByRowID(ctx, entity_id, id)
	case "tlscertificate":
		return r.fetchTLSCertificateByRowID(ctx, entity_id, id)
	case "url":
		return r.fetchURLByRowID(ctx, entity_id, id)
	}

	return nil, fmt.Errorf("unhandled table %q", table)
}
