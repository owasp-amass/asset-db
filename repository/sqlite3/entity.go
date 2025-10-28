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

// Params: :type_name, :dvalue, :attrs
const upsertEntitiesEntryText = `
WITH
	type_id AS (
		SELECT id FROM entity_type_lu WHERE name = :type_name LIMIT 1
	)
INSERT INTO entities(type_id, display_value, attrs) 
VALUES ((SELECT id FROM type_id), :dvalue, coalesce(:attrs,'{}')) 
ON CONFLICT(type_id, display_value) DO UPDATE SET 
    attrs = CASE WHEN json_patch(entities.attrs, coalesce(:attrs,'{}')) IS NOT entities.attrs
    THEN json_patch(entities.attrs, coalesce(:attrs,'{}')) ELSE entities.attrs END,
    updated_at = strftime('%Y-%m-%d %H:%M:%f','now');`

// Params: :type_name, :dvalue, :row_id
const upsertEntityRefEntryText = `
WITH
	type_id AS (
		SELECT id FROM entity_type_lu WHERE name = :type_name LIMIT 1
	),
	ent_id AS (
		SELECT entity_id FROM entities
        WHERE type_id = (SELECT id FROM type_id) 
		AND display_value = :dvalue LIMIT 1
	)
INSERT INTO entity_ref(entity_id, table_name, row_id)
VALUES ((SELECT entity_id FROM ent_id), :type_name, :row_id)
ON CONFLICT(table_name, row_id) DO UPDATE SET 
	entity_id=excluded.entity_id,
	updated_at=strftime('%Y-%m-%d %H:%M:%f','now');`

// Param: :type_name
const selectTypeIdByName = `
SELECT id FROM entity_type_lu
WHERE name = :type_name;`

// Entity models a row in `entities` plus its inlined concrete Asset.
// Attrs is raw JSON from entities.attrs (may be nil/"{}").
type Entity struct {
	EntityID     int64           `json:"entity_id"`
	Type         string          `json:"type"`          // entity_type_lu.name
	DisplayValue string          `json:"display_value"` // entities.display_value (normalized for some types)
	Attrs        json.RawMessage `json:"attrs"`         // entities.attrs
	Asset        any             `json:"asset"`         // concrete asset struct
}

func (r *SqliteRepository) CreateEntity(ctx context.Context, entity *types.Entity) (*types.Entity, error) {
	return r.CreateAsset(ctx, entity.Asset)
}

func (r *SqliteRepository) CreateAsset(ctx context.Context, asset oam.Asset) (*types.Entity, error) {
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
		eid, err = r.upsertFQDN(ctx, asset.(*oamdns.FQDN))
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
		eid, err = r.upsertNetblock(ctx, asset.(*oamnet.Netblock))
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
	return r.idToEntity(ctx, eid)
}

func (r *SqliteRepository) typeIdByName(ctx context.Context, tname string) (int64, error) {
	const keySel = "entity.type_id"
	stmt, err := r.queries.getOrPrepare(ctx, keySel, selectTypeIdByName)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := stmt.QueryRowContext(ctx,
		sql.Named("type_name", normalizeType(tname))).Scan(&id); err != nil {
		return 0, err
	}

	return id, nil
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

func (r *SqliteRepository) loadEntityCore(ctx context.Context, entityID int64) (*Entity, error) {
	var e Entity
	var raw string

	if err := r.queries.stmtEntityByID.QueryRowContext(ctx,
		entityID).Scan(&e.EntityID, &e.Type, &e.DisplayValue, &raw); err != nil {
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

func (r *SqliteRepository) fetchCompleteRepoEntity(ctx context.Context, e *Entity) (*types.Entity, error) {
	table := e.Type
	if table == "" {
		return nil, fmt.Errorf("no table mapping for entity type %q", e.Type)
	}

	// Resolve the row id in that concrete table via entity_ref
	var rowID int64
	if err := r.queries.stmtRefRowByEntityTable.QueryRowContext(ctx, e.EntityID, table).Scan(&rowID); err != nil {
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
func (r *SqliteRepository) fetchEntityAssetByTableID(ctx context.Context, entity_id int64, table string, id int64) (*types.Entity, error) {
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
