// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"errors"
	"net/netip"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/file"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/service"
)

func nodeToEntity(node neo4jdb.Node) (*types.Entity, error) {
	if node == nil {
		return nil, errors.New("the node is nil")
	}

	id, err := neo4jdb.GetProperty[string](node, "entity_id")
	if err != nil {
		return nil, err
	}

	created, err := neo4jdb.GetProperty[neo4jdb.LocalDateTime](node, "created_at")
	if err != nil {
		return nil, err
	}

	updated, err := neo4jdb.GetProperty[neo4jdb.LocalDateTime](node, "updated_at")
	if err != nil {
		return nil, err
	}

	etype, err := neo4jdb.GetProperty[string](node, "etype")
	if err != nil {
		return nil, err
	}
	atype := oam.AssetType(etype)

	var asset oam.Asset
	switch atype {
	case oam.AutnumRecord:
		asset, err = nodeToAutnumRecord(node)
	case oam.AutonomousSystem:
		asset, err = nodeToAutonomousSystem(node)
	case oam.ContactRecord:
		asset, err = nodeToContactRecord(node)
	case oam.DomainRecord:
		asset, err = nodeToDomainRecord(node)
	case oam.EmailAddress:
		asset, err = nodeToEmailAddress(node)
	case oam.File:
		asset, err = nodeToFile(node)
	case oam.FQDN:
		asset, err = nodeToFQDN(node)
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
	case oam.Service:
		asset, err = nodeToService(node)
	}
	if err != nil {
		return nil, err
	}

	return &types.Entity{
		ID:        id,
		CreatedAt: created,
		LastSeen:  updated,
		Asset:     asset,
	}, nil
}

func nodeToAutnumRecord(node neo4jdb.Node) (*oamreg.AutnumRecord, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
	}

	raw, err := neo4jdb.GetProperty[string](node, "raw")
	if err != nil {
		return nil, err
	}

	number, err := neo4jdb.GetProperty[int](node, "number")
	if err != nil {
		return nil, err
	}

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
	if node == nil {
		return nil, errors.New("The node is nil")
	}

	number, err := neo4jdb.GetProperty[int](node, "number")
	if err != nil {
		return nil, err
	}

	return &oamnet.AutonomousSystem{Number: number}, nil
}

func nodeToContactRecord(node neo4jdb.Node) (*contact.ContactRecord, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
	}

	discovered, err := neo4jdb.GetProperty[string](node, "discovered_at")
	if err != nil {
		return nil, err
	}

	return &contact.ContactRecord{DiscoveredAt: discovered}, nil
}

func nodeToDomainRecord(node neo4jdb.Node) (*oamreg.DomainRecord, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
	}

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

func nodeToEmailAddress(node neo4jdb.Node) (*contact.EmailAddress, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
	}

	address, err := neo4jdb.GetProperty[string](node, "address")
	if err != nil {
		return nil, err
	}

	username, err := neo4jdb.GetProperty[string](node, "username")
	if err != nil {
		return nil, err
	}

	domain, err := neo4jdb.GetProperty[string](node, "domain")
	if err != nil {
		return nil, err
	}

	return &contact.EmailAddress{
		Address:  address,
		Username: username,
		Domain:   domain,
	}, nil
}

func nodeToFile(node neo4jdb.Node) (*file.File, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
	}

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

func nodeToFQDN(node neo4jdb.Node) (*domain.FQDN, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
	}

	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	return &domain.FQDN{Name: name}, nil
}

func nodeToIPAddress(node neo4jdb.Node) (*oamnet.IPAddress, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
	}

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
	if node == nil {
		return nil, errors.New("The node is nil")
	}

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

	parent, err := neo4jdb.GetProperty[string](node, "parent")
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
	if node == nil {
		return nil, errors.New("The node is nil")
	}

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
	}, nil
}

func nodeToNetblock(node neo4jdb.Node) (*oamnet.Netblock, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
	}

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
	if node == nil {
		return nil, errors.New("The node is nil")
	}

	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	industry, err := neo4jdb.GetProperty[string](node, "industry")
	if err != nil {
		return nil, err
	}

	return &org.Organization{
		Name:     name,
		Industry: industry,
	}, nil
}

func nodeToPerson(node neo4jdb.Node) (*people.Person, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
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

	return &people.Person{
		FullName:   full,
		FirstName:  first,
		MiddleName: middle,
		FamilyName: family,
	}, nil
}

func nodeToPhone(node neo4jdb.Node) (*contact.Phone, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
	}

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

	code, err := neo4jdb.GetProperty[int](node, "country_code")
	if err != nil {
		return nil, err
	}

	ext, err := neo4jdb.GetProperty[string](node, "ext")
	if err != nil {
		return nil, err
	}

	return &contact.Phone{
		Type:          ptype,
		Raw:           raw,
		E164:          e164,
		CountryAbbrev: abbrev,
		CountryCode:   code,
		Ext:           ext,
	}, nil
}

func nodeToService(node neo4jdb.Node) (*service.Service, error) {
	if node == nil {
		return nil, errors.New("The node is nil")
	}

	ident, err := neo4jdb.GetProperty[string](node, "identifier")
	if err != nil {
		return nil, err
	}

	banner, err := neo4jdb.GetProperty[string](node, "banner")
	if err != nil {
		return nil, err
	}

	len, err := neo4jdb.GetProperty[int](node, "banner_length")
	if err != nil {
		return nil, err
	}

	return &service.Service{
		Identifier: ident,
		Banner:     banner,
		BannerLen:  len,
	}, nil
}
