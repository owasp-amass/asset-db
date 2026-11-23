// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"errors"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/account"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/file"
	"github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
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
	case oam.GeoLocation:
		asset, err = nodeToGeoLocation(node)
	case oam.Identifier:
		asset, err = nodeToIdentifier(node)
	case oam.IPAddress:
		asset, err = nodeToIPAddress(node)
	case oam.IPNetRecord:
		asset, err = nodeToIPNetRecord(node)
	case oam.StreetAddress:
		asset, err = nodeToStreetAddress(node)
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
	case oam.StorageBucket:
		asset, err = nodeToStorageBucket(node)
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

func nodeToContactRecord(node neo4jdb.Node) (*contact.ContactRecord, error) {
	discovered, err := neo4jdb.GetProperty[string](node, "discovered_at")
	if err != nil {
		return nil, err
	}

	return &contact.ContactRecord{DiscoveredAt: discovered}, nil
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

	// size was added later; a node stored before it has none
	var size int64
	if v, ok := node.Props["size"].(int64); ok {
		size = v
	}

	return &file.File{
		URL:  url,
		Name: name,
		Type: ftype,
		Size: size,
	}, nil
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

func nodeToGeoLocation(node neo4jdb.Node) (*contact.GeoLocation, error) {
	lat, err := neo4jdb.GetProperty[float64](node, "latitude")
	if err != nil {
		return nil, err
	}

	lon, err := neo4jdb.GetProperty[float64](node, "longitude")
	if err != nil {
		return nil, err
	}

	alt, err := neo4jdb.GetProperty[float64](node, "altitude")
	if err != nil {
		return nil, err
	}

	u, err := neo4jdb.GetProperty[float64](node, "uncertainty")
	if err != nil {
		return nil, err
	}

	return &contact.GeoLocation{
		Latitude:    lat,
		Longitude:   lon,
		Altitude:    alt,
		Uncertainty: u,
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

func nodeToStreetAddress(node neo4jdb.Node) (*contact.StreetAddress, error) {
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

	return &contact.StreetAddress{
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
