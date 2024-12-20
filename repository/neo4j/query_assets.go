// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"errors"
	"fmt"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/file"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/service"
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
	case *contact.EmailAddress:
		m["address"] = v.Address
		m["username"] = v.Username
		m["domain"] = v.Domain
	case *file.File:
		m["url"] = v.URL
		m["name"] = v.Name
		m["type"] = v.Type
	case *domain.FQDN:
		m["name"] = v.Name
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
		m["name"] = v.Name
		m["industry"] = v.Industry
	case *people.Person:
		m["full_name"] = v.FullName
		m["first_name"] = v.FirstName
		m["middle_name"] = v.MiddleName
		m["family_name"] = v.FamilyName
	case *contact.Phone:
		m["type"] = v.Type
		m["raw"] = v.Raw
		m["e164"] = v.E164
		m["country_abbrev"] = v.CountryAbbrev
		m["country_code"] = int64(v.CountryCode)
		m["ext"] = v.Ext
	case *service.Service:
		m["identifier"] = v.Identifier
		m["banner"] = v.Banner
		m["banner_length"] = int64(v.BannerLen)
		m["headers"] = v.Headers
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
	case *oamreg.AutnumRecord:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.AutnumRecord, "handle", v.Handle)
	case *oamnet.AutonomousSystem:
		node = fmt.Sprintf("(%s:%s {%s: %d})", varname, oam.AutonomousSystem, "number", v.Number)
	case *contact.ContactRecord:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.ContactRecord, "discovered_at", v.DiscoveredAt)
	case *oamreg.DomainRecord:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.DomainRecord, "domain", v.Domain)
	case *contact.EmailAddress:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.EmailAddress, "address", v.Address)
	case *file.File:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.File, "url", v.URL)
	case *domain.FQDN:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.FQDN, "name", v.Name)
	case *oamnet.IPAddress:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.IPAddress, "address", v.Address.String())
	case *oamreg.IPNetRecord:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.IPNetRecord, "handle", v.Handle)
	case *contact.Location:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Location, "address", v.Address)
	case *oamnet.Netblock:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Netblock, "cidr", v.CIDR.String())
	case *org.Organization:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Organization, "name", v.Name)
	case *people.Person:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Person, "full_name", v.FullName)
	case *contact.Phone:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Phone, "raw", v.Raw)
	case *service.Service:
		node = fmt.Sprintf("(%s:%s {%s: '%s'})", varname, oam.Service, "identifier", v.Identifier)
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
