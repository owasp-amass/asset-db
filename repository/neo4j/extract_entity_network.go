// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"net/netip"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

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

func nodeToFQDN(node neo4jdb.Node) (*dns.FQDN, error) {
	name, err := neo4jdb.GetProperty[string](node, "name")
	if err != nil {
		return nil, err
	}

	return &dns.FQDN{Name: name}, nil
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
