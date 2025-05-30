// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"encoding/json"
	"errors"
	"net/netip"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
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

func nodeToEntity(node neo4jdb.Node) (*types.Entity, error) {
	id, err := neo4jdb.GetProperty[string](node, "entity_id")
	if err != nil {
		return nil, err
	}

	t, err := neo4jdb.GetProperty[neo4jdb.LocalDateTime](node, "created_at")
	if err != nil {
		return nil, err
	}
	created := neo4jTimeToTime(t)

	t, err = neo4jdb.GetProperty[neo4jdb.LocalDateTime](node, "updated_at")
	if err != nil {
		return nil, err
	}
	updated := neo4jTimeToTime(t)

	etype, err := neo4jdb.GetProperty[string](node, "etype")
	if err != nil {
		return nil, err
	}
	atype := oam.AssetType(etype)

	var asset oam.Asset
	switch atype {
	case oam.Account:
		asset, err = nodeToAccount(node)
	case oam.AutnumRecord:
		asset, err = nodeToAutnumRecord(node)
	case oam.AutonomousSystem:
		asset, err = nodeToAutonomousSystem(node)
	case oam.ContactRecord:
		asset, err = nodeToContactRecord(node)
	case oam.DomainRecord:
		asset, err = nodeToDomainRecord(node)
	case oam.File:
		asset, err = nodeToFile(node)
	case oam.FQDN:
		asset, err = nodeToFQDN(node)
	case oam.FundsTransfer:
		asset, err = nodeToFundsTransfer(node)
	case oam.Identifier:
		asset, err = nodeToIdentifier(node)
	case oam.IPAddress:
		asset, err = nodeToIPAddress(node)
	case oam.IPNetRecord:
		asset, err = nodeToIPNetRecord(node)
	case oam.Location:
		asset, err = nodeToLocation(node)
	case oam.Netblock:
		asset, err = nodeToNetblock(node)
	case oam.Organization:
		asset, err = nodeToOrganization(node)
	case oam.Person:
		asset, err = nodeToPerson(node)
	case oam.Phone:
		asset, err = nodeToPhone(node)
	case oam.Product:
		asset, err = nodeToProduct(node)
	case oam.ProductRelease:
		asset, err = nodeToProductRelease(node)
	case oam.Service:
		asset, err = nodeToService(node)
	case oam.TLSCertificate:
		asset, err = nodeToTLSCertificate(node)
	case oam.URL:
		asset, err = nodeToURL(node)
	}
	if err != nil {
		return nil, err
	}
	if asset == nil {
		return nil, errors.New("asset type not supported")
	}

	return &types.Entity{
		ID:        id,
		CreatedAt: created,
		LastSeen:  updated,
		Asset:     asset,
	}, nil
}

func nodeToAccount(node neo4jdb.Node) (*account.Account, error) {
	id, err := neo4jdb.GetProperty[string](node, "unique_id")
	if err != nil {
		return nil, err
	}

	atype, err := neo4jdb.GetProperty[string](node, "account_type")
	if err != nil {
		return nil, err
	}

	user, err := neo4jdb.GetProperty[string](node, "username")
	if err != nil {
		return nil, err
	}

	number, err := neo4jdb.GetProperty[string](node, "account_number")
	if err != nil {
		return nil, err
	}

	balance, err := neo4jdb.GetProperty[float64](node, "balance")
	if err != nil {
		return nil, err
	}

	active, err := neo4jdb.GetProperty[bool](node, "active")
	if err != nil {
		return nil, err
	}

	return &account.Account{
		ID:       id,
		Type:     atype,
		Username: user,
		Number:   number,
		Balance:  balance,
		Active:   active,
	}, nil
}

func nodeToAutnumRecord(node neo4jdb.Node) (*oamreg.AutnumRecord, error) {
	raw, err := neo4jdb.GetProperty[string](node, "raw")
	if err != nil {
		return nil, err
	}

	num, err := neo4jdb.GetProperty[int64](node, "number")
	if err != nil {
		return nil, err
	}
	number := int(num)

	handle, err := neo4jdb.GetProperty[string](node, "handle")
	if err != nil {
		return nil, err
	}

	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	whois, err := neo4jdb.GetProperty[string](node, "whois_server")
	if err != nil {
		return nil, err
	}

	created, err := neo4jdb.GetProperty[string](node, "created_date")
	if err != nil {
		return nil, err
	}

	updated, err := neo4jdb.GetProperty[string](node, "updated_date")
	if err != nil {
		return nil, err
	}

	list, err := neo4jdb.GetProperty[[]interface{}](node, "status")
	if err != nil {
		return nil, err
	}

	var status []string
	for _, s := range list {
		status = append(status, s.(string))
	}

	return &oamreg.AutnumRecord{
		Raw:         raw,
		Number:      number,
		Handle:      handle,
		Name:        name,
		WhoisServer: whois,
		CreatedDate: created,
		UpdatedDate: updated,
		Status:      status,
	}, nil
}

func nodeToAutonomousSystem(node neo4jdb.Node) (*oamnet.AutonomousSystem, error) {
	num, err := neo4jdb.GetProperty[int64](node, "number")
	if err != nil {
		return nil, err
	}
	number := int(num)

	return &oamnet.AutonomousSystem{Number: number}, nil
}

func nodeToContactRecord(node neo4jdb.Node) (*contact.ContactRecord, error) {
	discovered, err := neo4jdb.GetProperty[string](node, "discovered_at")
	if err != nil {
		return nil, err
	}

	return &contact.ContactRecord{DiscoveredAt: discovered}, nil
}

func nodeToDomainRecord(node neo4jdb.Node) (*oamreg.DomainRecord, error) {
	raw, err := neo4jdb.GetProperty[string](node, "raw")
	if err != nil {
		return nil, err
	}

	id, err := neo4jdb.GetProperty[string](node, "id")
	if err != nil {
		return nil, err
	}

	domain, err := neo4jdb.GetProperty[string](node, "domain")
	if err != nil {
		return nil, err
	}

	punny, err := neo4jdb.GetProperty[string](node, "punycode")
	if err != nil {
		return nil, err
	}

	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	ext, err := neo4jdb.GetProperty[string](node, "extension")
	if err != nil {
		return nil, err
	}

	whois, err := neo4jdb.GetProperty[string](node, "whois_server")
	if err != nil {
		return nil, err
	}

	created, err := neo4jdb.GetProperty[string](node, "created_date")
	if err != nil {
		return nil, err
	}

	updated, err := neo4jdb.GetProperty[string](node, "updated_date")
	if err != nil {
		return nil, err
	}

	expiration, err := neo4jdb.GetProperty[string](node, "expiration_date")
	if err != nil {
		return nil, err
	}

	list, err := neo4jdb.GetProperty[[]interface{}](node, "status")
	if err != nil {
		return nil, err
	}

	var status []string
	for _, s := range list {
		status = append(status, s.(string))
	}

	dnssec, err := neo4jdb.GetProperty[bool](node, "dnssec")
	if err != nil {
		return nil, err
	}

	return &oamreg.DomainRecord{
		Raw:            raw,
		ID:             id,
		Domain:         domain,
		Punycode:       punny,
		Name:           name,
		Extension:      ext,
		WhoisServer:    whois,
		CreatedDate:    created,
		UpdatedDate:    updated,
		ExpirationDate: expiration,
		Status:         status,
		DNSSEC:         dnssec,
	}, nil
}

func nodeToFile(node neo4jdb.Node) (*file.File, error) {
	url, err := neo4jdb.GetProperty[string](node, "url")
	if err != nil {
		return nil, err
	}

	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	ftype, err := neo4jdb.GetProperty[string](node, "type")
	if err != nil {
		return nil, err
	}

	return &file.File{
		URL:  url,
		Name: name,
		Type: ftype,
	}, nil
}

func nodeToFQDN(node neo4jdb.Node) (*dns.FQDN, error) {
	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	return &dns.FQDN{Name: name}, nil
}

func nodeToFundsTransfer(node neo4jdb.Node) (*financial.FundsTransfer, error) {
	id, err := neo4jdb.GetProperty[string](node, "unique_id")
	if err != nil {
		return nil, err
	}

	amount, err := neo4jdb.GetProperty[float64](node, "amount")
	if err != nil {
		return nil, err
	}

	ref, err := neo4jdb.GetProperty[string](node, "reference_number")
	if err != nil {
		return nil, err
	}

	currency, err := neo4jdb.GetProperty[string](node, "currency")
	if err != nil {
		return nil, err
	}

	method, err := neo4jdb.GetProperty[string](node, "transfer_method")
	if err != nil {
		return nil, err
	}

	date, err := neo4jdb.GetProperty[string](node, "exchange_date")
	if err != nil {
		return nil, err
	}

	rate, err := neo4jdb.GetProperty[float64](node, "exchange_rate")
	if err != nil {
		return nil, err
	}

	return &financial.FundsTransfer{
		ID:              id,
		Amount:          amount,
		ReferenceNumber: ref,
		Currency:        currency,
		Method:          method,
		ExchangeDate:    date,
		ExchangeRate:    rate,
	}, nil
}

func nodeToIdentifier(node neo4jdb.Node) (*general.Identifier, error) {
	uid, err := neo4jdb.GetProperty[string](node, "unique_id")
	if err != nil {
		return nil, err
	}

	eid, err := neo4jdb.GetProperty[string](node, "id")
	if err != nil {
		return nil, err
	}

	idtype, err := neo4jdb.GetProperty[string](node, "id_type")
	if err != nil {
		return nil, err
	}

	cd, err := neo4jdb.GetProperty[string](node, "creation_date")
	if err != nil {
		return nil, err
	}

	ud, err := neo4jdb.GetProperty[string](node, "update_date")
	if err != nil {
		return nil, err
	}

	ed, err := neo4jdb.GetProperty[string](node, "expiration_date")
	if err != nil {
		return nil, err
	}

	status, err := neo4jdb.GetProperty[string](node, "status")
	if err != nil {
		return nil, err
	}

	return &general.Identifier{
		UniqueID:       uid,
		ID:             eid,
		Type:           idtype,
		CreationDate:   cd,
		UpdatedDate:    ud,
		ExpirationDate: ed,
		Status:         status,
	}, nil
}

func nodeToIPAddress(node neo4jdb.Node) (*oamnet.IPAddress, error) {
	ip, err := neo4jdb.GetProperty[string](node, "address")
	if err != nil {
		return nil, err
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, err
	}

	iptype, err := neo4jdb.GetProperty[string](node, "type")
	if err != nil {
		return nil, err
	}

	return &oamnet.IPAddress{
		Address: addr,
		Type:    iptype,
	}, nil
}

func nodeToIPNetRecord(node neo4jdb.Node) (*oamreg.IPNetRecord, error) {
	raw, err := neo4jdb.GetProperty[string](node, "raw")
	if err != nil {
		return nil, err
	}

	cidr, err := neo4jdb.GetProperty[string](node, "cidr")
	if err != nil {
		return nil, err
	}

	ipnet, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}

	handle, err := neo4jdb.GetProperty[string](node, "handle")
	if err != nil {
		return nil, err
	}

	addr, err := neo4jdb.GetProperty[string](node, "start_address")
	if err != nil {
		return nil, err
	}

	start, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	addr, err = neo4jdb.GetProperty[string](node, "end_address")
	if err != nil {
		return nil, err
	}

	end, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	rectype, err := neo4jdb.GetProperty[string](node, "type")
	if err != nil {
		return nil, err
	}

	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	method, err := neo4jdb.GetProperty[string](node, "method")
	if err != nil {
		return nil, err
	}

	country, err := neo4jdb.GetProperty[string](node, "country")
	if err != nil {
		return nil, err
	}

	parent, err := neo4jdb.GetProperty[string](node, "parent_handle")
	if err != nil {
		return nil, err
	}

	whois, err := neo4jdb.GetProperty[string](node, "whois_server")
	if err != nil {
		return nil, err
	}

	created, err := neo4jdb.GetProperty[string](node, "created_date")
	if err != nil {
		return nil, err
	}

	updated, err := neo4jdb.GetProperty[string](node, "updated_date")
	if err != nil {
		return nil, err
	}

	list, err := neo4jdb.GetProperty[[]interface{}](node, "status")
	if err != nil {
		return nil, err
	}

	var status []string
	for _, s := range list {
		status = append(status, s.(string))
	}

	return &oamreg.IPNetRecord{
		Raw:          raw,
		CIDR:         ipnet,
		Handle:       handle,
		StartAddress: start,
		EndAddress:   end,
		Type:         rectype,
		Name:         name,
		Method:       method,
		Country:      country,
		ParentHandle: parent,
		WhoisServer:  whois,
		CreatedDate:  created,
		UpdatedDate:  updated,
		Status:       status,
	}, nil
}

func nodeToLocation(node neo4jdb.Node) (*contact.Location, error) {
	addr, err := neo4jdb.GetProperty[string](node, "address")
	if err != nil {
		return nil, err
	}

	building, err := neo4jdb.GetProperty[string](node, "building")
	if err != nil {
		return nil, err
	}

	bnum, err := neo4jdb.GetProperty[string](node, "building_number")
	if err != nil {
		return nil, err
	}

	street, err := neo4jdb.GetProperty[string](node, "street_name")
	if err != nil {
		return nil, err
	}

	unit, err := neo4jdb.GetProperty[string](node, "unit")
	if err != nil {
		return nil, err
	}

	pobox, err := neo4jdb.GetProperty[string](node, "po_box")
	if err != nil {
		return nil, err
	}

	city, err := neo4jdb.GetProperty[string](node, "city")
	if err != nil {
		return nil, err
	}

	locality, err := neo4jdb.GetProperty[string](node, "locality")
	if err != nil {
		return nil, err
	}

	province, err := neo4jdb.GetProperty[string](node, "province")
	if err != nil {
		return nil, err
	}

	country, err := neo4jdb.GetProperty[string](node, "country")
	if err != nil {
		return nil, err
	}

	postal, err := neo4jdb.GetProperty[string](node, "postal_code")
	if err != nil {
		return nil, err
	}

	num, err := neo4jdb.GetProperty[int64](node, "gln")
	if err != nil {
		return nil, err
	}
	gln := int(num)

	return &contact.Location{
		Address:        addr,
		Building:       building,
		BuildingNumber: bnum,
		StreetName:     street,
		Unit:           unit,
		POBox:          pobox,
		City:           city,
		Locality:       locality,
		Province:       province,
		Country:        country,
		PostalCode:     postal,
		GLN:            gln,
	}, nil
}

func nodeToNetblock(node neo4jdb.Node) (*oamnet.Netblock, error) {
	cidr, err := neo4jdb.GetProperty[string](node, "cidr")
	if err != nil {
		return nil, err
	}

	ipnet, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}

	ntype, err := neo4jdb.GetProperty[string](node, "type")
	if err != nil {
		return nil, err
	}

	return &oamnet.Netblock{
		CIDR: ipnet,
		Type: ntype,
	}, nil
}

func nodeToOrganization(node neo4jdb.Node) (*org.Organization, error) {
	id, err := neo4jdb.GetProperty[string](node, "unique_id")
	if err != nil {
		return nil, err
	}

	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	lname, err := neo4jdb.GetProperty[string](node, "legal_name")
	if err != nil {
		return nil, err
	}

	date, err := neo4jdb.GetProperty[string](node, "founding_date")
	if err != nil {
		return nil, err
	}

	juris, err := neo4jdb.GetProperty[string](node, "jurisdiction")
	if err != nil {
		return nil, err
	}

	regid, err := neo4jdb.GetProperty[string](node, "registration_id")
	if err != nil {
		return nil, err
	}

	industry, err := neo4jdb.GetProperty[string](node, "industry")
	if err != nil {
		return nil, err
	}

	active, err := neo4jdb.GetProperty[bool](node, "active")
	if err != nil {
		return nil, err
	}

	nonprofit, err := neo4jdb.GetProperty[bool](node, "non_profit")
	if err != nil {
		return nil, err
	}

	num, err := neo4jdb.GetProperty[int64](node, "headcount")
	if err != nil {
		return nil, err
	}
	employees := int(num)

	return &org.Organization{
		ID:             id,
		Name:           name,
		LegalName:      lname,
		FoundingDate:   date,
		Jurisdiction:   juris,
		RegistrationID: regid,
		Industry:       industry,
		Active:         active,
		NonProfit:      nonprofit,
		Headcount:      employees,
	}, nil
}

func nodeToPerson(node neo4jdb.Node) (*people.Person, error) {
	id, err := neo4jdb.GetProperty[string](node, "unique_id")
	if err != nil {
		return nil, err
	}

	full, err := neo4jdb.GetProperty[string](node, "full_name")
	if err != nil {
		return nil, err
	}

	first, err := neo4jdb.GetProperty[string](node, "first_name")
	if err != nil {
		return nil, err
	}

	middle, err := neo4jdb.GetProperty[string](node, "middle_name")
	if err != nil {
		return nil, err
	}

	family, err := neo4jdb.GetProperty[string](node, "family_name")
	if err != nil {
		return nil, err
	}

	birth, err := neo4jdb.GetProperty[string](node, "birth_date")
	if err != nil {
		return nil, err
	}

	gender, err := neo4jdb.GetProperty[string](node, "gender")
	if err != nil {
		return nil, err
	}

	return &people.Person{
		ID:         id,
		FullName:   full,
		FirstName:  first,
		MiddleName: middle,
		FamilyName: family,
		BirthDate:  birth,
		Gender:     gender,
	}, nil
}

func nodeToPhone(node neo4jdb.Node) (*contact.Phone, error) {
	ptype, err := neo4jdb.GetProperty[string](node, "type")
	if err != nil {
		return nil, err
	}

	raw, err := neo4jdb.GetProperty[string](node, "raw")
	if err != nil {
		return nil, err
	}

	e164, err := neo4jdb.GetProperty[string](node, "e164")
	if err != nil {
		return nil, err
	}

	abbrev, err := neo4jdb.GetProperty[string](node, "country_abbrev")
	if err != nil {
		return nil, err
	}

	code, err := neo4jdb.GetProperty[int64](node, "country_code")
	if err != nil {
		return nil, err
	}
	cc := int(code)

	ext, err := neo4jdb.GetProperty[string](node, "ext")
	if err != nil {
		return nil, err
	}

	return &contact.Phone{
		Type:          ptype,
		Raw:           raw,
		E164:          e164,
		CountryAbbrev: abbrev,
		CountryCode:   cc,
		Ext:           ext,
	}, nil
}

func nodeToProduct(node neo4jdb.Node) (*platform.Product, error) {
	ident, err := neo4jdb.GetProperty[string](node, "unique_id")
	if err != nil {
		return nil, err
	}

	name, err := neo4jdb.GetProperty[string](node, "product_name")
	if err != nil {
		return nil, err
	}

	ptype, err := neo4jdb.GetProperty[string](node, "product_type")
	if err != nil {
		return nil, err
	}

	category, err := neo4jdb.GetProperty[string](node, "category")
	if err != nil {
		return nil, err
	}

	desc, err := neo4jdb.GetProperty[string](node, "description")
	if err != nil {
		return nil, err
	}

	country, err := neo4jdb.GetProperty[string](node, "country_of_origin")
	if err != nil {
		return nil, err
	}

	return &platform.Product{
		ID:              ident,
		Name:            name,
		Type:            ptype,
		Category:        category,
		Description:     desc,
		CountryOfOrigin: country,
	}, nil
}

func nodeToProductRelease(node neo4jdb.Node) (*platform.ProductRelease, error) {
	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	date, err := neo4jdb.GetProperty[string](node, "release_date")
	if err != nil {
		return nil, err
	}

	return &platform.ProductRelease{
		Name:        name,
		ReleaseDate: date,
	}, nil
}

func nodeToService(node neo4jdb.Node) (*platform.Service, error) {
	ident, err := neo4jdb.GetProperty[string](node, "unique_id")
	if err != nil {
		return nil, err
	}

	stype, err := neo4jdb.GetProperty[string](node, "service_type")
	if err != nil {
		return nil, err
	}

	output, err := neo4jdb.GetProperty[string](node, "output")
	if err != nil {
		return nil, err
	}

	l, err := neo4jdb.GetProperty[int64](node, "output_length")
	if err != nil {
		return nil, err
	}
	olen := int(l)

	attrs, err := neo4jdb.GetProperty[string](node, "attributes")
	if err != nil {
		return nil, err
	}

	var m map[string][]string
	if attrs != "" {
		if err := json.Unmarshal([]byte(attrs), &m); err != nil {
			return nil, err
		}
	}

	return &platform.Service{
		ID:         ident,
		Type:       stype,
		Output:     output,
		OutputLen:  olen,
		Attributes: m,
	}, nil
}

func nodeToTLSCertificate(node neo4jdb.Node) (*oamcert.TLSCertificate, error) {
	version, err := neo4jdb.GetProperty[string](node, "version")
	if err != nil {
		return nil, err
	}

	serial, err := neo4jdb.GetProperty[string](node, "serial_number")
	if err != nil {
		return nil, err
	}

	subjectCommon, err := neo4jdb.GetProperty[string](node, "subject_common_name")
	if err != nil {
		return nil, err
	}

	issuer, err := neo4jdb.GetProperty[string](node, "issuer_common_name")
	if err != nil {
		return nil, err
	}

	before, err := neo4jdb.GetProperty[string](node, "not_before")
	if err != nil {
		return nil, err
	}

	after, err := neo4jdb.GetProperty[string](node, "not_after")
	if err != nil {
		return nil, err
	}

	list, err := neo4jdb.GetProperty[[]interface{}](node, "key_usage")
	if err != nil {
		return nil, err
	}

	var keyUsage []string
	for _, s := range list {
		keyUsage = append(keyUsage, s.(string))
	}

	list, err = neo4jdb.GetProperty[[]interface{}](node, "ext_key_usage")
	if err != nil {
		return nil, err
	}

	var extKeyUsage []string
	for _, s := range list {
		extKeyUsage = append(extKeyUsage, s.(string))
	}

	sig, err := neo4jdb.GetProperty[string](node, "signature_algorithm")
	if err != nil {
		return nil, err
	}

	public, err := neo4jdb.GetProperty[string](node, "public_key_algorithm")
	if err != nil {
		return nil, err
	}

	isCA, err := neo4jdb.GetProperty[bool](node, "is_ca")
	if err != nil {
		return nil, err
	}

	list, err = neo4jdb.GetProperty[[]interface{}](node, "crl_distribution_points")
	if err != nil {
		return nil, err
	}

	var dist []string
	for _, s := range list {
		dist = append(dist, s.(string))
	}

	subjectKey, err := neo4jdb.GetProperty[string](node, "subject_key_id")
	if err != nil {
		return nil, err
	}

	autorityKey, err := neo4jdb.GetProperty[string](node, "authority_key_id")
	if err != nil {
		return nil, err
	}

	return &oamcert.TLSCertificate{
		Version:               version,
		SerialNumber:          serial,
		SubjectCommonName:     subjectCommon,
		IssuerCommonName:      issuer,
		NotBefore:             before,
		NotAfter:              after,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		SignatureAlgorithm:    sig,
		PublicKeyAlgorithm:    public,
		IsCA:                  isCA,
		CRLDistributionPoints: dist,
		SubjectKeyID:          subjectKey,
		AuthorityKeyID:        autorityKey,
	}, nil
}

func nodeToURL(node neo4jdb.Node) (*url.URL, error) {
	raw, err := neo4jdb.GetProperty[string](node, "url")
	if err != nil {
		return nil, err
	}

	scheme, err := neo4jdb.GetProperty[string](node, "scheme")
	if err != nil {
		return nil, err
	}

	username, err := neo4jdb.GetProperty[string](node, "username")
	if err != nil {
		return nil, err
	}

	password, err := neo4jdb.GetProperty[string](node, "password")
	if err != nil {
		return nil, err
	}

	host, err := neo4jdb.GetProperty[string](node, "host")
	if err != nil {
		return nil, err
	}

	p, err := neo4jdb.GetProperty[int64](node, "port")
	if err != nil {
		return nil, err
	}
	port := int(p)

	path, err := neo4jdb.GetProperty[string](node, "path")
	if err != nil {
		return nil, err
	}

	options, err := neo4jdb.GetProperty[string](node, "options")
	if err != nil {
		return nil, err
	}

	frag, err := neo4jdb.GetProperty[string](node, "fragment")
	if err != nil {
		return nil, err
	}

	return &url.URL{
		Raw:      raw,
		Scheme:   scheme,
		Username: username,
		Password: password,
		Host:     host,
		Port:     port,
		Path:     path,
		Options:  options,
		Fragment: frag,
	}, nil
}
