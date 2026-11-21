// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	dbt "github.com/owasp-amass/asset-db/types"
)

// MaxEntitiesByIds is the most IDs FindEntitiesByIds reads at once.
const MaxEntitiesByIds = 1000

// Params: @ids::bigint[]
const selectEntityTypesByIdsText = `
SELECT e.entity_id, lower(et.name) FROM public.entity e
JOIN public.entity_type_lu et ON et.id = e.etype_id
WHERE e.entity_id = ANY(@ids::bigint[]);`

// entitiesByIdsReader reads the entities of one asset type by entity ID:
// its query (params @ids::bigint[]) returns the columns its scan expects.
type entitiesByIdsReader struct {
	query string
	scan  func(r *PostgresRepository, ctx context.Context, query string, args pgx.NamedArgs) ([]*dbt.Entity, error)
}

var entitiesByIdsReaders = map[string]entitiesByIdsReader{
	"account": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.account_type, a.username,
a.account_number, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.account_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanAccounts,
	},
	"autnumrecord": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.handle, a.asn, a.record_name,
a.whois_server, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.autnumrecord_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanAutnumRecords,
	},
	"autonomoussystem": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.asn, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.autonomoussystem_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanAutonomousSystems,
	},
	"contactrecord": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.discovered_at, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.contactrecord_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanContactRecords,
	},
	"domainrecord": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.domain, a.record_name, a.punycode,
a.extension, a.whois_server, a.object_id, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.domainrecord_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanDomainRecords,
	},
	"file": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.file_url, a.basename, a.file_type, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.file_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanFiles,
	},
	"fqdn": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.fqdn, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.fqdn_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanFQDNs,
	},
	"fundstransfer": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.amount, a.reference_number,
a.attrs
FROM public.entity e CROSS JOIN LATERAL public.fundstransfer_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanFundsTransfers,
	},
	"geolocation": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.latitude, a.longitude,
a.altitude, a.uncertainty
FROM public.entity e CROSS JOIN LATERAL public.geolocation_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanGeoLocations,
	},
	"identifier": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.id_value, a.id_type, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.identifier_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanIdentifiers,
	},
	"ipaddress": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.ip_address, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.ipaddress_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanIPAddresses,
	},
	"ipnetrecord": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.record_cidr, a.record_name, a.handle,
a.whois_server, a.parent_handle, a.start_address, a.end_address, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.ipnetrecord_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanIPNetRecords,
	},
	"netblock": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.netblock_cidr, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.netblock_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanNetblocks,
	},
	"organization": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.org_name, a.legal_name,
a.jurisdiction, a.registration_id, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.organization_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanOrganizations,
	},
	"person": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.full_name, a.first_name,
a.family_name, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.person_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanPersons,
	},
	"phone": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.e164, a.country_code, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.phone_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanPhones,
	},
	"product": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.product_name, a.product_type,
a.attrs
FROM public.entity e CROSS JOIN LATERAL public.product_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanProducts,
	},
	"productrelease": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.release_name, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.productrelease_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanProductReleases,
	},
	"service": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.service_type, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.service_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanServices,
	},
	"storagebucket": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.unique_id, a.bucket_name, a.provider,
a.service, a.bucket_exists, a.is_public
FROM public.entity e CROSS JOIN LATERAL public.storagebucket_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanStorageBuckets,
	},
	"streetaddress": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.street_address, a.city, a.country, a.unit,
a.building, a.province, a.locality, a.postal_code, a.street_name, a.building_number, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.streetaddress_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanStreetAddresses,
	},
	"tlscertificate": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.serial_number, a.subject_common_name,
a.attrs
FROM public.entity e CROSS JOIN LATERAL public.tlscertificate_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanTLSCertificates,
	},
	"url": {
		query: `
SELECT e.entity_id, a.id, a.created_at, a.updated_at, a.raw_url, a.scheme, a.attrs
FROM public.entity e CROSS JOIN LATERAL public.url_get_by_id(e.row_id) AS a
WHERE e.entity_id = ANY(@ids::bigint[]);`,
		scan: (*PostgresRepository).scanURLs,
	},
}

// FindEntitiesByIds returns the entities with the given IDs, with their
// assets, in the order of ids. An ID with no entity is left out. It reads
// with one query for the entities' types and one per asset type, where
// FindEntityById takes two queries for each entity.
func (r *PostgresRepository) FindEntitiesByIds(ctx context.Context, ids []string) ([]*dbt.Entity, error) {
	if r == nil || r.rpool == nil {
		return nil, errors.New("missing PostgreSQL reader")
	}
	if len(ids) > MaxEntitiesByIds {
		return nil, fmt.Errorf("at most %d entity IDs may be read at once", MaxEntitiesByIds)
	}

	eids := make([]int64, 0, len(ids))
	for _, id := range ids {
		eid, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid entity ID %q: %w", id, err)
		}

		eids = append(eids, eid)
	}
	if len(eids) == 0 {
		return nil, nil
	}

	byType := map[string][]int64{}
	j := NewRowsJob(ctx, selectEntityTypesByIdsText, pgx.NamedArgs{"ids": eids}, func(rows pgx.Rows) error {
		for rows.Next() {
			var eid int64
			var etype string
			if err := rows.Scan(&eid, &etype); err != nil {
				return err
			}

			byType[etype] = append(byType[etype], eid)
		}

		return rows.Err()
	})
	r.rpool.Submit(j)
	if err := j.Wait(); err != nil {
		return nil, err
	}

	found := make(map[string]*dbt.Entity, len(eids))
	for etype, group := range byType {
		reader, ok := entitiesByIdsReaders[etype]
		if !ok {
			return nil, fmt.Errorf("unhandled entity type %q", etype)
		}

		ents, err := reader.scan(r, ctx, reader.query, pgx.NamedArgs{"ids": group})
		if err != nil {
			return nil, err
		}

		r.remember(ents...)
		for _, e := range ents {
			found[e.ID] = e
		}
	}

	out := make([]*dbt.Entity, 0, len(found))
	for _, id := range ids {
		if e, ok := found[id]; ok {
			out = append(out, e)
		}
	}

	return out, nil
}
