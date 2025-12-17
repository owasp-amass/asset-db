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
	etype, err := r.loadEntityCore(ctx, eid)
	if err != nil {
		return nil, err
	}

	return r.fetchCompleteRepoEntity(ctx, eid, etype)
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
	table := normalizeType(atype)
	if table == "" {
		return nil, fmt.Errorf("unknown asset type %q", atype)
	}

	// Normalize/validate filters against registry for that table.
	reg, ok := contentRegistry[table]
	if !ok {
		return nil, fmt.Errorf("no content registry for table %q", table)
	}

	where, args, err := buildWhere(table, reg, since, filters)
	if err != nil {
		return nil, err
	}

	// Query entity ids via join to the concrete asset table.
	sb := strings.Builder{}
	sb.WriteString(`
SELECT e.entity_id FROM entity e
JOIN entity_type_lu t ON t.id = e.etype_id AND t.name = ? 
JOIN ` + table + ` a ON a.id = e.row_id`)

	args = append([]any{table}, args...) // prepend type/table to args
	if where != "" {
		sb.WriteString(" WHERE " + where + "\n")
	}
	sb.WriteString("ORDER BY e.updated_at DESC")
	if limit > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
	}

	q := sb.String()
	key := "q.findByContent." + table + "." + where + fmt.Sprintf("limit%d", limit)

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{
		Ctx:     ctx,
		Name:    key,
		SQLText: q,
		Args:    args,
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	var out []*dbt.Entity
	for result.Rows.Next() {
		var eid int64

		if err := result.Rows.Scan(&eid); err != nil {
			return nil, err
		}
		ent, err := r.idToEntity(ctx, eid)
		if err != nil {
			return nil, err
		}

		out = append(out, ent)
	}

	return out, result.Rows.Err()
}

// findByType returns up to `limit` Entities of the given asset type,
// ordered by most recently updated (DESC). Each Entity has its concrete Asset populated.
//
// If limit <= 0, it returns all (be careful on large datasets).
func (r *PostgresRepository) findByType(ctx context.Context, atype string, since time.Time, limit int) ([]*dbt.Entity, error) {
	table := normalizeType(atype)
	// Build SQL (parameterized LIMIT only if > 0, to keep a stable prepared key)
	base := `
SELECT e.entity_id, e.natural_key
FROM entity e
JOIN entity_type_lu t ON t.id = e.etype_id AND t.name = ?`
	key := "entity.by_type.base"
	q := base
	args := []any{table}

	if !since.IsZero() {
		key += ".since"
		q += " WHERE e.updated_at >= ?"
		args = append(args, since.UTC())
	}

	q += " ORDER BY e.updated_at DESC, e.entity_id DESC"

	if limit > 0 {
		key += fmt.Sprintf(".limit%d", limit)
		q = base + " LIMIT ?"
		args = append(args, limit)
	}

	ch := make(chan *rowsReadResult, 1)
	r.rpool.Submit(&rowsReadJob{
		Ctx:     ctx,
		Name:    key,
		SQLText: q,
		Args:    args,
		Result:  ch,
	})

	result := <-ch
	if result.Err != nil {
		return nil, result.Err
	}
	defer func() { _ = result.Rows.Close() }()

	out := make([]*dbt.Entity, 0, max(0, limit))
	for result.Rows.Next() {
		var eid int64
		var disp string
		if err := result.Rows.Scan(&eid, &disp); err != nil {
			return nil, err
		}
		// Hydrate via existing logic (populates Type + Asset)
		ent, err := r.idToEntity(ctx, eid)
		if err != nil {
			return nil, err
		}
		out = append(out, ent)
	}
	return out, result.Rows.Err()
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

func (r *PostgresRepository) loadEntityCore(ctx context.Context, eid int64) (string, error) {
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

func (r *PostgresRepository) fetchCompleteRepoEntity(ctx context.Context, eid int64, etype string) (*dbt.Entity, error) {
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
		const qSel = `SELECT table_name, row_id FROM entity WHERE entity_id = :entity_id LIMIT 1`
		ch := make(chan *rowReadResult, 1)
		r.rpool.Submit(&rowReadJob{
			Ctx:     ctx,
			Name:    "entity.delete.table_row_from_id",
			SQLText: qSel,
			Args:    []any{sql.Named("entity_id", eid)},
			Result:  ch,
		})

		result := <-ch
		if result.Err != nil {
			return result.Err
		}

		var t string
		var id int64
		if err := result.Row.Scan(&t, &id); err != nil {
			return err
		}

		if tbl := validateAssetTable(t); tbl != "" {
			done := make(chan error, 1)
			r.ww.Submit(&writeJob{
				Ctx:     ctx,
				Name:    "asset." + tbl + ".delete_by_id",
				SQLText: fmt.Sprintf(`DELETE FROM %s WHERE id = :row_id`, tbl),
				Args:    []any{sql.Named("row_id", id)},
				Result:  done,
			})
			if err := <-done; err != nil {
				return err
			}
		}
	}

	// Delete the entity (FKs should take care of edges, tag maps if schema has CASCADE)
	done := make(chan error, 1)
	r.ww.Submit(&writeJob{
		Ctx:     ctx,
		Name:    "entity.delete.by_id",
		SQLText: `DELETE FROM entity WHERE entity_id = :entity_id`,
		Args:    []any{sql.Named("entity_id", eid)},
		Result:  done,
	})
	return <-done
}
