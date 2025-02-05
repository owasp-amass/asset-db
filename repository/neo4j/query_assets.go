// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"errors"
	"fmt"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/account"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/file"
	"github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	"github.com/owasp-amass/open-asset-model/platform"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/url"
)

func entityPropsMap(entity *types.Entity) (map[string]interface{}, error) {
	if entity == nil {
		return nil, errors.New("the entity is nil")
	}
	if entity.Asset == nil {
		return nil, errors.New("the asset is nil")
	}

	m := make(map[string]interface{})
	// begin populating the map of parameters
	m["etype"] = entity.Asset.AssetType()
	m["entity_id"] = entity.ID
	m["created_at"] = timeToNeo4jTime(entity.CreatedAt)
	m["updated_at"] = timeToNeo4jTime(entity.LastSeen)

	switch v := entity.Asset.(type) {
	case *account.Account:
		m["unique_id"] = v.ID
		m["account_type"] = v.Type
		m["username"] = v.Username
		m["account_number"] = v.Number
		m["balance"] = v.Balance
		m["active"] = v.Active
	case *oamreg.AutnumRecord:
		m["raw"] = v.Raw
		m["number"] = int64(v.Number)
		m["handle"] = v.Handle
		m["name"] = v.Name
		m["whois_server"] = v.WhoisServer
		m["created_date"] = v.CreatedDate
		m["updated_date"] = v.UpdatedDate
		m["status"] = v.Status
	case *oamnet.AutonomousSystem:
		m["number"] = int64(v.Number)
	case *contact.ContactRecord:
		m["discovered_at"] = v.DiscoveredAt
	case *oamreg.DomainRecord:
		m["raw"] = v.Raw
		m["id"] = v.ID
		m["domain"] = v.Domain
		m["punycode"] = v.Punycode
		m["name"] = v.Name
		m["extension"] = v.Extension
		m["whois_server"] = v.WhoisServer
		m["created_date"] = v.CreatedDate
		m["updated_date"] = v.UpdatedDate
		m["expiration_date"] = v.ExpirationDate
		m["status"] = v.Status
		m["dnssec"] = v.DNSSEC
	case *file.File:
		m["url"] = v.URL
		m["name"] = v.Name
		m["type"] = v.Type
	case *dns.FQDN:
		m["name"] = v.Name
	case *financial.FundsTransfer:
		m["unique_id"] = v.ID
		m["amount"] = v.Amount
		m["reference_number"] = v.ReferenceNumber
		m["currency"] = v.Currency
		m["transfer_method"] = v.Method
		m["exchange_date"] = v.ExchangeDate
		m["exchange_rate"] = v.ExchangeRate
	case *general.Identifier:
		m["unique_id"] = v.UniqueID
		m["entity_id"] = v.EntityID
		m["id_type"] = v.Type
		m["category"] = v.Category
		m["creation_date"] = v.CreationDate
		m["update_date"] = v.UpdatedDate
		m["expiration_date"] = v.ExpirationDate
		m["status"] = v.Status
	case *oamnet.IPAddress:
		m["address"] = v.Address.String()
		m["type"] = v.Type
	case *oamreg.IPNetRecord:
		m["raw"] = v.Raw
		m["cidr"] = v.CIDR.String()
		m["handle"] = v.Handle
		m["start_address"] = v.StartAddress.String()
		m["end_address"] = v.EndAddress.String()
		m["type"] = v.Type
		m["name"] = v.Name
		m["method"] = v.Method
		m["country"] = v.Country
		m["parent_handle"] = v.ParentHandle
		m["whois_server"] = v.WhoisServer
		m["created_date"] = v.CreatedDate
		m["updated_date"] = v.UpdatedDate
		m["status"] = v.Status
	case *contact.Location:
		m["address"] = v.Address
		m["building"] = v.Building
		m["building_number"] = v.BuildingNumber
		m["street_name"] = v.StreetName
		m["unit"] = v.Unit
		m["po_box"] = v.POBox
		m["city"] = v.City
		m["locality"] = v.Locality
		m["province"] = v.Province
		m["country"] = v.Country
		m["postal_code"] = v.PostalCode
	case *oamnet.Netblock:
		m["cidr"] = v.CIDR.String()
		m["type"] = v.Type
	case *org.Organization:
		m["unique_id"] = v.ID
		m["name"] = v.Name
		m["legal_name"] = v.LegalName
		m["founding_date"] = v.FoundingDate
		m["industry"] = v.Industry
		m["active"] = v.Active
		m["non_profit"] = v.NonProfit
		m["num_of_employees"] = int64(v.NumOfEmployees)
	case *people.Person:
		m["unique_id"] = v.ID
		m["full_name"] = v.FullName
		m["first_name"] = v.FirstName
		m["middle_name"] = v.MiddleName
		m["family_name"] = v.FamilyName
		m["birth_date"] = v.BirthDate
		m["gender"] = v.Gender
	case *contact.Phone:
		m["type"] = v.Type
		m["raw"] = v.Raw
		m["e164"] = v.E164
		m["country_abbrev"] = v.CountryAbbrev
		m["country_code"] = int64(v.CountryCode)
		m["ext"] = v.Ext
	case *platform.Product:
		m["unique_id"] = v.ID
		m["product_name"] = v.Name
		m["product_type"] = v.Type
		m["category"] = v.Category
		m["description"] = v.Description
		m["country_of_origin"] = v.CountryOfOrigin
	case *platform.ProductRelease:
		m["name"] = v.Name
		m["release_date"] = v.ReleaseDate
	case *platform.Service:
		m["unique_id"] = v.ID
		m["service_type"] = v.Type
		m["output"] = v.Output
		m["output_length"] = int64(v.OutputLen)
		m["attributes"] = v.Attributes
	case *oamcert.TLSCertificate:
		m["version"] = v.Version
		m["serial_number"] = v.SerialNumber
		m["subject_common_name"] = v.SubjectCommonName
		m["issuer_common_name"] = v.IssuerCommonName
		m["not_before"] = v.NotBefore
		m["not_after"] = v.NotAfter
		m["key_usage"] = v.KeyUsage
		m["ext_key_usage"] = v.ExtKeyUsage
		m["signature_algorithm"] = v.SignatureAlgorithm
		m["public_key_algorithm"] = v.PublicKeyAlgorithm
		m["is_ca"] = v.IsCA
		m["crl_distribution_points"] = v.CRLDistributionPoints
		m["subject_key_id"] = v.SubjectKeyID
		m["authority_key_id"] = v.AuthorityKeyID
	case *url.URL:
		m["url"] = v.Raw
		m["scheme"] = v.Scheme
		m["username"] = v.Username
		m["password"] = v.Password
		m["host"] = v.Host
		m["port"] = int64(v.Port)
		m["path"] = v.Path
		m["options"] = v.Options
		m["fragment"] = v.Fragment
	default:
		return nil, errors.New("asset type not supported")
	}

	return m, nil
}

func queryNodeByAssetKey(varname string, asset oam.Asset) (string, error) {
	if asset == nil {
		return "", errors.New("the asset is nil")
	}

	var node string
	switch v := asset.(type) {
	case *account.Account:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Account, "unique_id", v.ID)
	case *oamreg.AutnumRecord:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.AutnumRecord, "handle", v.Handle)
	case *oamnet.AutonomousSystem:
		node = fmt.Sprintf("(%s:%s {%s: %d})", varname, oam.AutonomousSystem, "number", v.Number)
	case *contact.ContactRecord:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.ContactRecord, "discovered_at", v.DiscoveredAt)
	case *oamreg.DomainRecord:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.DomainRecord, "domain", v.Domain)
	case *file.File:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.File, "url", v.URL)
	case *dns.FQDN:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.FQDN, "name", v.Name)
	case *financial.FundsTransfer:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.FundsTransfer, "unique_id", v.ID)
	case *general.Identifier:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Identifier, "unique_id", v.UniqueID)
	case *oamnet.IPAddress:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.IPAddress, "address", v.Address.String())
	case *oamreg.IPNetRecord:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.IPNetRecord, "handle", v.Handle)
	case *contact.Location:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Location, "address", v.Address)
	case *oamnet.Netblock:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Netblock, "cidr", v.CIDR.String())
	case *org.Organization:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Organization, "unique_id", v.ID)
	case *people.Person:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Person, "unique_id", v.ID)
	case *contact.Phone:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Phone, "raw", v.Raw)
	case *platform.Product:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Product, "unique_id", v.ID)
	case *platform.ProductRelease:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.ProductRelease, "name", v.Name)
	case *platform.Service:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Service, "unique_id", v.ID)
	case *oamcert.TLSCertificate:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.TLSCertificate, "serial_number", v.SerialNumber)
	case *url.URL:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.URL, "url", v.Raw)
	}
	if node == "" {
		return "", errors.New("asset type not supported")
	}

	return node, nil
}
