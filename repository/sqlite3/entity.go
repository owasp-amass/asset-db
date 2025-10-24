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
)

// Entity models a row in `entities` plus its inlined concrete Asset.
// Attrs is raw JSON from entities.attrs (may be nil/"{}").
type Entity struct {
	EntityID     int64           `json:"entity_id"`
	Type         string          `json:"type"`          // entity_type_lu.name
	DisplayValue string          `json:"display_value"` // entities.display_value (normalized for some types)
	Attrs        json.RawMessage `json:"attrs"`         // entities.attrs
	Asset        any             `json:"asset"`         // one of the asset structs below
}

// FindEntityByID returns the Entity (with Asset populated) for a given entity_id.
func (r *Queries) FindEntityByID(ctx context.Context, entityID int64) (*Entity, error) {
	e, err := r.loadEntityCore(ctx, entityID)
	if err != nil {
		return nil, err
	}
	if err := r.populateAsset(ctx, e); err != nil {
		return nil, err
	}
	return e, nil
}

// FindByAssetPK returns Entity/Asset for a specific table primary key id.
func (r *Queries) FindByAssetPK(ctx context.Context, tableName string, rowID int64) (*Entity, error) {
	table := normalizeTable(tableName)
	var eid int64
	if err := r.stmtEntityIDByAssetPK.QueryRowContext(ctx, table, rowID).Scan(&eid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no entity for %s(%d)", table, rowID)
		}
		return nil, err
	}
	return r.FindEntityByID(ctx, eid)
}

// FindByTypeAndValue returns Entity/Asset by asset type and its display value.
// For types requiring normalization (fqdn/domainrecord), normalization is applied.
func (r *Queries) FindByTypeAndValue(ctx context.Context, assetType, value string) (*Entity, error) {
	t := normalizeType(assetType)
	v := normalizeValueForType(t, value)

	var eid int64
	if err := r.stmtEntityIDByTypeValue.QueryRowContext(ctx, t, v).Scan(&eid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no entity for type=%s value=%q", t, value)
		}
		return nil, err
	}
	return r.FindEntityByID(ctx, eid)
}

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

func (r *Queries) populateAsset(ctx context.Context, e *Entity) error {
	table := e.Type
	if table == "" {
		return fmt.Errorf("no table mapping for entity type %q", e.Type)
	}
	// Resolve the row id in that concrete table via entity_ref
	var rowID int64
	if err := r.stmtRefRowByEntityTable.QueryRowContext(ctx, e.EntityID, table).Scan(&rowID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Entity exists but does not have a ref to the expected table (data drift)
			return fmt.Errorf("entity %d has no %s row mapping", e.EntityID, table)
		}
		return err
	}
	asset, err := r.fetchAssetByTableID(ctx, table, rowID)
	if err != nil {
		return err
	}
	e.Asset = asset
	return nil
}

// fetchAssetByTableID selects the concrete asset row and scans into its struct.
// Statements are prepared lazily and cached per table name.
func (r *Queries) fetchAssetByTableID(ctx context.Context, table string, id int64) (any, error) {
	switch table {
	case "account":
		return r.fetchAccountByRowID(ctx, id)
	case "autnumrecord":
		return r.fetchAutnumRecordByRowID(ctx, id)
	case "autonomoussystem":
		return r.fetchAutonomousSystemByRowID(ctx, id)
	case "contactrecord":
		return r.fetchContactRecordByRowID(ctx, id)
	case "domainrecord":
		return r.fetchDomainRecordByRowID(ctx, id)
	case "file":
		return r.fetchFileByRowID(ctx, id)
	case "fqdn":
		return r.fetchFQDNByRowID(ctx, id)
	case "fundstransfer":
		return r.fetchFundsTransferByRowID(ctx, id)
	case "identifier":
		return r.fetchIdentifierByRowID(ctx, id)
	case "ipaddress":
		return r.fetchIPAddressByRowID(ctx, id)
	case "ipnetrecord":
		return r.fetchIPNetRecordByRowID(ctx, id)
	case "location":
		return r.fetchLocationByRowID(ctx, id)
	case "netblock":
		return r.fetchNetblockByRowID(ctx, id)
	case "organization":
		return r.fetchOrganizationByRowID(ctx, id)
	case "person":
		return r.fetchPersonByRowID(ctx, id)
	case "phone":
		return r.fetchPhoneByRowID(ctx, id)
	case "product":
		return r.fetchProductByRowID(ctx, id)
	case "productrelease":
		return r.fetchProductReleaseByRowID(ctx, id)
	case "service":
		return r.fetchServiceByRowID(ctx, id)
	case "tlscertificate":
		return r.fetchTLSCertificateByRowID(ctx, id)
	case "url":
		return r.fetchURLByRowID(ctx, id)
	}

	return nil, fmt.Errorf("unhandled table %q", table)
}
