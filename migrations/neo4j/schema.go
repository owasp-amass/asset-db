// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func InitializeSchema(driver neo4jdb.DriverWithContext, dbname string) error {
	_ = executeQuery(driver, dbname, "CREATE DATABASE "+dbname+" IF NOT EXISTS")
	_ = executeQuery(driver, dbname, "START DATABASE "+dbname+" WAIT 10 SECONDS")

	err := executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_entities_entity_id IF NOT EXISTS FOR (n:Entity) REQUIRE n.entity_id IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE INDEX entities_range_index_etype IF NOT EXISTS FOR (n:Entity) ON (n.etype)")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE INDEX entities_range_index_updated_at IF NOT EXISTS FOR (n:Entity) ON (n.updated_at)")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_enttag_tag_id IF NOT EXISTS FOR (n:EntityTag) REQUIRE n.tag_id IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE INDEX enttag_range_index_ttype IF NOT EXISTS FOR (n:EntityTag) ON (n.ttype)")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE INDEX enttag_range_index_updated_at IF NOT EXISTS FOR (n:EntityTag) ON (n.updated_at)")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE INDEX enttag_range_index_entity_id IF NOT EXISTS FOR (n:EntityTag) ON (n.entity_id)")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_edgetag_tag_id IF NOT EXISTS FOR (n:EdgeTag) REQUIRE n.tag_id IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE INDEX edgetag_range_index_ttype IF NOT EXISTS FOR (n:EdgeTag) ON (n.ttype)")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE INDEX edgetag_range_index_updated_at IF NOT EXISTS FOR (n:EdgeTag) ON (n.updated_at)")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE INDEX edgetag_range_index_edge_id IF NOT EXISTS FOR (n:EdgeTag) ON (n.edge_id)")
	if err != nil {
		return err
	}

	return entitiesContentIndexes(driver, dbname)
}

func entitiesContentIndexes(driver neo4jdb.DriverWithContext, dbname string) error {
	err := executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_account_content_unique_id IF NOT EXISTS FOR (n:Account) REQUIRE n.unique_id IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_autnum_content_handle IF NOT EXISTS FOR (n:AutnumRecord) REQUIRE n.handle IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_autnum_content_number IF NOT EXISTS FOR (n:AutnumRecord) REQUIRE n.number IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_autsys_content_number IF NOT EXISTS FOR (n:AutonomousSystem) REQUIRE n.number IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_domainrec_content_domain IF NOT EXISTS FOR (n:DomainRecord) REQUIRE n.domain IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_file_content_url IF NOT EXISTS FOR (n:File) REQUIRE n.url IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_fqdn_content_name IF NOT EXISTS FOR (n:FQDN) REQUIRE n.name IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_ft_content_unique_id IF NOT EXISTS FOR (n:FundsTransfer) REQUIRE n.unique_id IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_identifier_content_id IF NOT EXISTS FOR (n:Identifier) REQUIRE n.id IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_ipaddr_content_address IF NOT EXISTS FOR (n:IPAddress) REQUIRE n.address IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_ipnetrec_content_cidr IF NOT EXISTS FOR (n:IPNetRecord) REQUIRE n.cidr IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_ipnetrec_content_handle IF NOT EXISTS FOR (n:IPNetRecord) REQUIRE n.handle IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_location_content_name IF NOT EXISTS FOR (n:Location) REQUIRE n.address IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_netblock_content_cidr IF NOT EXISTS FOR (n:Netblock) REQUIRE n.cidr IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_org_content_id IF NOT EXISTS FOR (n:Organization) REQUIRE n.unique_id IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE INDEX org_range_index_name IF NOT EXISTS FOR (n:Organization) ON (n.name)")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_org_content_legal_name IF NOT EXISTS FOR (n:Organization) REQUIRE n.legal_name IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE INDEX person_range_index_full_name IF NOT EXISTS FOR (n:Person) ON (n.full_name)")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_phone_content_raw IF NOT EXISTS FOR (n:Phone) REQUIRE n.raw IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_product_content_id IF NOT EXISTS FOR (n:Product) REQUIRE n.unique_id IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_productrelease_content_name IF NOT EXISTS FOR (n:ProductRelease) REQUIRE n.name IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_service_content_id IF NOT EXISTS FOR (n:Service) REQUIRE n.unique_id IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_tls_content_serial_number IF NOT EXISTS FOR (n:TLSCertificate) REQUIRE n.serial_number IS UNIQUE")
	if err != nil {
		return err
	}

	err = executeQuery(driver, dbname, "CREATE CONSTRAINT constraint_url_content_url IF NOT EXISTS FOR (n:URL) REQUIRE n.url IS UNIQUE")
	if err != nil {
		return err
	}
	return nil
}

func executeQuery(driver neo4jdb.DriverWithContext, dbname, query string) error {
	_, err := neo4jdb.ExecuteQuery(context.Background(), driver,
		query, nil, neo4jdb.EagerResultTransformer, neo4jdb.ExecuteQueryWithDatabase(dbname))
	return err
}
