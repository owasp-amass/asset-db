// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
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

func (r *PostgresRepository) CreateEntity(ctx context.Context, entity *dbt.Entity) (*dbt.Entity, error) {
	return r.CreateAsset(ctx, entity.Asset)
}

func (r *PostgresRepository) CreateAsset(ctx context.Context, asset oam.Asset) (*dbt.Entity, error) {
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

// FindEntityById implements the Repository interface.
func (r *PostgresRepository) FindEntityById(ctx context.Context, id string) (*dbt.Entity, error) {
	entityId, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	return r.idToEntity(ctx, entityId)
}

func (r *PostgresRepository) idToEntity(ctx context.Context, eid int64) (*dbt.Entity, error) {
	return r.fetchCompleteRepoEntity(ctx, eid)
}

func (r *PostgresRepository) FindEntitiesByContent(ctx context.Context, atype oam.AssetType, since time.Time, filters dbt.ContentFilters) ([]*dbt.Entity, error) {
	ents, err := r.findByContent(ctx, string(atype), since, filters, 0)
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		return nil, errors.New("zero entities found")
	}
	return ents, nil
}

func (r *PostgresRepository) FindOneEntityByContent(ctx context.Context, atype oam.AssetType, since time.Time, filters dbt.ContentFilters) (*dbt.Entity, error) {
	ent, err := r.findOneByContent(ctx, string(atype), since, filters)
	if err != nil {
		return nil, err
	}
	if ent == nil {
		return nil, errors.New("entity not found")
	}
	return ent, nil
}

func (r *PostgresRepository) FindEntitiesByType(ctx context.Context, atype oam.AssetType, since time.Time) ([]*dbt.Entity, error) {
	ents, err := r.findByType(ctx, string(atype), since, 0)
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		return nil, errors.New("zero entities found")
	}
	return ents, nil
}

// findByContent builds the SQL WHERE from a registry of allowed columns per
// asset type, and returns Entity+Asset. Supports multiple matches.

// findOneByContent returns exactly one (first by updated_at desc)
func (r *PostgresRepository) findOneByContent(ctx context.Context, atype string, since time.Time, filters dbt.ContentFilters) (*dbt.Entity, error) {
	ents, err := r.findByContent(ctx, atype, since, filters, 1)
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		return nil, errors.New("zero entities found")
	}
	return ents[0], nil
}

// findByContent finds entities for asset type with given filters (on the asset table).
// limit <= 0 => no explicit LIMIT.
func (r *PostgresRepository) findByContent(ctx context.Context, atype string, since time.Time, filters dbt.ContentFilters, limit int) ([]*dbt.Entity, error) {
	etype := normalizeType(atype)
	if etype == "" {
		return nil, fmt.Errorf("unknown asset type %q", atype)
	}

	switch etype {
	case "account":
		return r.findAccountsByContent(ctx, filters, since, limit)
	case "autnumrecord":
		return r.findAutnumRecordsByContent(ctx, filters, since, limit)
	case "autonomoussystem":
		return r.findAutonomousSystemsByContent(ctx, filters, since, limit)
	case "contactrecord":
		return r.findContactRecordsByContent(ctx, filters, since, limit)
	case "domainrecord":
		return r.findDomainRecordsByContent(ctx, filters, since, limit)
	case "file":
		return r.findFilesByContent(ctx, filters, since, limit)
	case "fqdn":
		return r.findFQDNsByContent(ctx, filters, since, limit)
	case "fundstransfer":
		return r.findFundsTransfersByContent(ctx, filters, since, limit)
	case "identifier":
		return r.findIdentifiersByContent(ctx, filters, since, limit)
	case "ipaddress":
		return r.findIPAddressesByContent(ctx, filters, since, limit)
	case "ipnetrecord":
		return r.findIPNetRecordsByContent(ctx, filters, since, limit)
	case "location":
		return r.findLocationsByContent(ctx, filters, since, limit)
	case "netblock":
		return r.findNetblocksByContent(ctx, filters, since, limit)
	case "organization":
		return r.findOrganizationsByContent(ctx, filters, since, limit)
	case "person":
		return r.findPersonsByContent(ctx, filters, since, limit)
	case "phone":
		return r.findPhonesByContent(ctx, filters, since, limit)
	case "product":
		return r.findProductsByContent(ctx, filters, since, limit)
	case "productrelease":
		return r.findProductReleasesByContent(ctx, filters, since, limit)
	case "service":
		return r.findServicesByContent(ctx, filters, since, limit)
	case "tlscertificate":
		return r.findTLSCertificatesByContent(ctx, filters, since, limit)
	case "url":
		return r.findURLsByContent(ctx, filters, since, limit)
	}

	return nil, fmt.Errorf("content search not implemented for asset type %q", atype)
}

// findByType returns up to `limit` Entities of the given asset type,
// ordered by most recently updated (DESC). Each Entity has its concrete Asset populated.
//
// If limit <= 0, it returns all (be careful on large datasets).
func (r *PostgresRepository) findByType(ctx context.Context, atype string, since time.Time, limit int) ([]*dbt.Entity, error) {
	etype := normalizeType(atype)
	if etype == "" {
		return nil, fmt.Errorf("unknown asset type %q", atype)
	}

	switch etype {
	case "account":
		return r.getAccountsUpdatedSince(ctx, since, limit)
	case "autnumrecord":
		return r.getAutnumRecordsUpdatedSince(ctx, since, limit)
	case "autonomoussystem":
		return r.getAutonomousSystemsUpdatedSince(ctx, since, limit)
	case "contactrecord":
		return r.getContactRecordsUpdatedSince(ctx, since, limit)
	case "domainrecord":
		return r.getDomainRecordsUpdatedSince(ctx, since, limit)
	case "file":
		return r.getFilesUpdatedSince(ctx, since, limit)
	case "fqdn":
		return r.getFQDNsUpdatedSince(ctx, since, limit)
	case "fundstransfer":
		return r.getFundsTransfersUpdatedSince(ctx, since, limit)
	case "identifier":
		return r.getIdentifiersUpdatedSince(ctx, since, limit)
	case "ipaddress":
		return r.getIPAddressesUpdatedSince(ctx, since, limit)
	case "ipnetrecord":
		return r.getIPNetRecordsUpdatedSince(ctx, since, limit)
	case "location":
		return r.getLocationsUpdatedSince(ctx, since, limit)
	case "netblock":
		return r.getNetblocksUpdatedSince(ctx, since, limit)
	case "organization":
		return r.getOrganizationsUpdatedSince(ctx, since, limit)
	case "person":
		return r.getPersonsUpdatedSince(ctx, since, limit)
	case "phone":
		return r.getPhonesUpdatedSince(ctx, since, limit)
	case "product":
		return r.getProductsUpdatedSince(ctx, since, limit)
	case "productrelease":
		return r.getProductReleasesUpdatedSince(ctx, since, limit)
	case "service":
		return r.getServicesUpdatedSince(ctx, since, limit)
	case "tlscertificate":
		return r.getTLSCertificatesUpdatedSince(ctx, since, limit)
	case "url":
		return r.getURLsUpdatedSince(ctx, since, limit)
	}

	return nil, fmt.Errorf("type search not implemented for asset type %q", atype)
}

// --- tiny helper used above ---
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ============================== Asset hydration ==============================

func normalizeType(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func (r *PostgresRepository) fetchEntityTypeAndRowID(ctx context.Context, eid int64) (string, int64, error) {
	ch := make(chan *rowResult, 1)
	r.wpool.Submit(&rowJob{
		Ctx:     ctx,
		Name:    "entity.type_row_by_id",
		SQLText: `SELECT e.etype_name, e.row_id FROM public.entity_get_by_id(@entity_id::bigint) AS e;`,
		Args:    pgx.NamedArgs{"entity_id": eid},
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return "", 0, result.Err
	}

	var etype string
	var rowID int64
	if err := result.Row.Scan(&etype, &rowID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", 0, fmt.Errorf("entity %d not found", eid)
		}
		return "", 0, err
	}

	return etype, rowID, nil
}

func (r *PostgresRepository) fetchCompleteRepoEntity(ctx context.Context, eid int64) (*dbt.Entity, error) {
	etype, rid, err := r.fetchEntityTypeAndRowID(ctx, eid)
	if err != nil {
		return nil, err
	}

	return r.fetchEntityAssetByTableID(ctx, eid, etype, rid)
}

// fetchEntityAssetByTableID selects the concrete asset row and scans into its struct.
// Statements are prepared lazily and cached per table name.
func (r *PostgresRepository) fetchEntityAssetByTableID(ctx context.Context, entity_id int64, etype string, id int64) (*dbt.Entity, error) {
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

func (r *PostgresRepository) DeleteEntity(ctx context.Context, id string) error {
	eid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}
	return r.deleteEntityByID(ctx, eid, true)
}

// deleteEntityByID deletes a single entity and (via FK CASCADE) its incident edges
// and tag mappings. It leaves the concrete asset row intact by default; if you also
// want to remove the asset row, set alsoDeleteAsset=true.
func (r *PostgresRepository) deleteEntityByID(ctx context.Context, eid int64, alsoDeleteAsset bool) error {
	// Optionally remove the concrete asset row (requires looking up its table + row_id)
	if alsoDeleteAsset {
		const qSel = `SELECT table_name, row_id FROM entity WHERE entity_id = @entity_id LIMIT 1`
		ch := make(chan *rowResult, 1)
		r.wpool.Submit(&rowJob{
			Ctx:     ctx,
			Name:    "entity.delete.table_row_from_id",
			SQLText: qSel,
			Args:    pgx.NamedArgs{"entity_id": eid},
			Result:  ch,
		})

		result := <-ch
		if result.Err != nil {
			return result.Err
		}

		var id int64
		var table string
		if err := result.Row.Scan(&table, &id); err != nil {
			return err
		}

		if table != "" {
			done := make(chan error, 1)
			r.wpool.Submit(&execJob{
				Ctx:     ctx,
				Name:    "asset." + table + ".delete_by_id",
				SQLText: fmt.Sprintf(`DELETE FROM %s WHERE id = @row_id`, table),
				Args:    pgx.NamedArgs{"row_id": id},
				Result:  done,
			})
			if err := <-done; err != nil {
				return err
			}
		}
	}

	// Delete the entity (FKs should take care of edges, tag maps if schema has CASCADE)
	done := make(chan error, 1)
	r.wpool.Submit(&execJob{
		Ctx:     ctx,
		Name:    "entity.delete.by_id",
		SQLText: `DELETE FROM entity WHERE entity_id = @entity_id`,
		Args:    pgx.NamedArgs{"entity_id": eid},
		Result:  done,
	})
	return <-done
}
