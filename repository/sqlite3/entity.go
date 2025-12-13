// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
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

func (r *SqliteRepository) CreateEntity(ctx context.Context, entity *dbt.Entity) (*dbt.Entity, error) {
	return r.CreateAsset(ctx, entity.Asset)
}

func (r *SqliteRepository) CreateAsset(ctx context.Context, asset oam.Asset) (*dbt.Entity, error) {
	var eid int64
	var err error

	switch asset.AssetType() {
	case oam.Account:
		eid, err = r.upsertAccount(ctx, asset.(*oamacct.Account))
	case oam.AutnumRecord:
		eid, err = r.upsertAutnumRecord(ctx, asset.(*oamreg.AutnumRecord))
	case oam.AutonomousSystem:
		eid, err = r.upsertAutonomousSystem(ctx, asset.(*oamnet.AutonomousSystem))
	case oam.ContactRecord:
		eid, err = r.upsertContactRecord(ctx, asset.(*contact.ContactRecord))
	case oam.DomainRecord:
		eid, err = r.upsertDomainRecord(ctx, asset.(*oamreg.DomainRecord))
	case oam.File:
		eid, err = r.upsertFile(ctx, asset.(*oamfile.File))
	case oam.FQDN:
		eid, err = r.upsertFQDN(ctx, asset.(*oamdns.FQDN))
	case oam.FundsTransfer:
		eid, err = r.upsertFundsTransfer(ctx, asset.(*oamfin.FundsTransfer))
	case oam.Identifier:
		eid, err = r.upsertIdentifier(ctx, asset.(*oamgen.Identifier))
	case oam.IPAddress:
		eid, err = r.upsertIPAddress(ctx, asset.(*oamnet.IPAddress))
	case oam.IPNetRecord:
		eid, err = r.upsertIPNetRecord(ctx, asset.(*oamreg.IPNetRecord))
	case oam.Location:
		eid, err = r.upsertLocation(ctx, asset.(*contact.Location))
	case oam.Netblock:
		eid, err = r.upsertNetblock(ctx, asset.(*oamnet.Netblock))
	case oam.Organization:
		eid, err = r.upsertOrganization(ctx, asset.(*oamorg.Organization))
	case oam.Person:
		eid, err = r.upsertPerson(ctx, asset.(*people.Person))
	case oam.Phone:
		eid, err = r.upsertPhone(ctx, asset.(*contact.Phone))
	case oam.Product:
		eid, err = r.upsertProduct(ctx, asset.(*oamplat.Product))
	case oam.ProductRelease:
		eid, err = r.upsertProductRelease(ctx, asset.(*oamplat.ProductRelease))
	case oam.Service:
		eid, err = r.upsertService(ctx, asset.(*oamplat.Service))
	case oam.TLSCertificate:
		eid, err = r.upsertTLSCertificate(ctx, asset.(*oamcert.TLSCertificate))
	case oam.URL:
		eid, err = r.upsertURL(ctx, asset.(*oamurl.URL))
	default:
		return nil, fmt.Errorf("unsupported asset type %q", asset.AssetType())
	}

	if err != nil {
		return nil, err
	}
	return r.idToEntity(ctx, eid)
}

// ============================== Asset hydration ==============================

func normalizeType(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

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

func (r *SqliteRepository) loadEntityCore(ctx context.Context, eid int64) (string, error) {
	query := `
	SELECT t.name
	FROM entity_type_lu t
	JOIN entity e ON t.id = e.etype_id
	WHERE e.entity_id = :entity_id`

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "entity.by_id",
		SQLText: query,
		Args:    []any{sql.Named("entity_id", eid)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return "", result.Err
	}

	var etype string
	if err := result.Row.Scan(&etype); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("entity %d not found", eid)
		}
		return "", err
	}

	return etype, nil
}

func (r *SqliteRepository) fetchCompleteRepoEntity(ctx context.Context, eid int64, etype string) (*dbt.Entity, error) {
	if etype == "" {
		return nil, fmt.Errorf("invalid entity type %q", etype)
	}

	ch := make(chan *rowReadResult, 1)
	r.rpool.Submit(&rowReadJob{
		Ctx:     ctx,
		Name:    "entity.row_by_id",
		SQLText: `SELECT row_id FROM entity WHERE entity_id = :entity_id LIMIT 1`,
		Args:    []any{sql.Named("entity_id", eid)},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}

	var rid int64
	if err := result.Row.Scan(&rid); err != nil {
		return nil, err
	}

	return r.fetchEntityAssetByTableID(ctx, eid, etype, rid)
}

// fetchEntityAssetByTableID selects the concrete asset row and scans into its struct.
// Statements are prepared lazily and cached per table name.
func (r *SqliteRepository) fetchEntityAssetByTableID(ctx context.Context, entity_id int64, etype string, id int64) (*dbt.Entity, error) {
	switch etype {
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

	return nil, fmt.Errorf("unhandled entity type %q", etype)
}
