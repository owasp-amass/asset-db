// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"encoding/json"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/platform"
	"github.com/owasp-amass/open-asset-model/url"
)

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

func nodeToStorageBucket(node neo4jdb.Node) (*platform.StorageBucket, error) {
	ident, err := neo4jdb.GetProperty[string](node, "unique_id")
	if err != nil {
		return nil, err
	}

	name, err := neo4jdb.GetProperty[string](node, "bucket_name")
	if err != nil {
		return nil, err
	}

	provider, err := neo4jdb.GetProperty[string](node, "provider")
	if err != nil {
		return nil, err
	}

	service, err := neo4jdb.GetProperty[string](node, "service")
	if err != nil {
		return nil, err
	}

	exists, err := neo4jdb.GetProperty[bool](node, "bucket_exists")
	if err != nil {
		return nil, err
	}

	public, err := neo4jdb.GetProperty[bool](node, "is_public")
	if err != nil {
		return nil, err
	}

	return &platform.StorageBucket{
		ID:       ident,
		Name:     name,
		Provider: provider,
		Service:  service,
		Exists:   exists,
		Public:   public,
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

	// public_key_sha256 was added later; nodes written before it lack the
	// property, so a missing value is empty rather than an error.
	publicKeyHash, _ := neo4jdb.GetProperty[string](node, "public_key_sha256")

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
		PublicKeySHA256:       publicKeyHash,
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
