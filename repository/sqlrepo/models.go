// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlrepo

import (
	"encoding/json"
	"fmt"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/account"
	oamtls "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/dns"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	"github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	"github.com/owasp-amass/open-asset-model/platform"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/url"
	"gorm.io/datatypes"
)

// Entity represents an entity stored in the database.
type Entity struct {
	ID        uint64    `gorm:"primaryKey;column:entity_id"`
	CreatedAt time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column:created_at"`
	UpdatedAt time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column:updated_at"`
	Type      string    `gorm:"column:etype"`
	Content   datatypes.JSON
}

// EntityTag represents additional metadata added to an entity in the asset database.
type EntityTag struct {
	ID        uint64    `gorm:"primaryKey;column:tag_id"`
	CreatedAt time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column:created_at"`
	UpdatedAt time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column:updated_at"`
	Type      string    `gorm:"column:ttype"`
	Content   datatypes.JSON
	EntityID  uint64 `gorm:"column:entity_id"`
}

// Edge represents a relationship between two entities stored in the database.
type Edge struct {
	ID           uint64    `gorm:"primaryKey;column:edge_id"`
	CreatedAt    time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column:created_at"`
	UpdatedAt    time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column:updated_at"`
	Type         string    `gorm:"column:etype"`
	Content      datatypes.JSON
	FromEntityID uint64 `gorm:"column:from_entity_id"`
	ToEntityID   uint64 `gorm:"column:to_entity_id"`
	FromEntity   Entity
	ToEntity     Entity
}

// EdgeTag represents additional metadata added to an edge in the asset database.
type EdgeTag struct {
	ID        uint64    `gorm:"primaryKey;column:tag_id"`
	CreatedAt time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column:created_at"`
	UpdatedAt time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column:updated_at"`
	Type      string    `gorm:"column:ttype"`
	Content   datatypes.JSON
	EdgeID    uint64 `gorm:"column:edge_id"`
}

// Parse parses the content of the entity into the corresponding Open Asset Model (OAM) asset type.
// It returns the parsed asset and an error, if any.
func (e *Entity) Parse() (oam.Asset, error) {
	var err error
	var asset oam.Asset

	switch e.Type {
	case string(oam.Account):
		var a account.Account

		err = json.Unmarshal(e.Content, &a)
		asset = &a
	case string(oam.AutnumRecord):
		var ar oamreg.AutnumRecord

		err = json.Unmarshal(e.Content, &ar)
		asset = &ar
	case string(oam.AutonomousSystem):
		var as network.AutonomousSystem

		err = json.Unmarshal(e.Content, &as)
		asset = &as
	case string(oam.ContactRecord):
		var cr contact.ContactRecord

		err = json.Unmarshal(e.Content, &cr)
		asset = &cr
	case string(oam.DomainRecord):
		var dr oamreg.DomainRecord

		err = json.Unmarshal(e.Content, &dr)
		asset = &dr
	case string(oam.File):
		var f oamfile.File

		err = json.Unmarshal(e.Content, &f)
		asset = &f
	case string(oam.FQDN):
		var fqdn dns.FQDN

		err = json.Unmarshal(e.Content, &fqdn)
		asset = &fqdn
	case string(oam.FundsTransfer):
		var ft financial.FundsTransfer

		err = json.Unmarshal(e.Content, &ft)
		asset = &ft
	case string(oam.Identifier):
		var id general.Identifier

		err = json.Unmarshal(e.Content, &id)
		asset = &id
	case string(oam.IPAddress):
		var ip network.IPAddress

		err = json.Unmarshal(e.Content, &ip)
		asset = &ip
	case string(oam.IPNetRecord):
		var ipnetrec oamreg.IPNetRecord

		err = json.Unmarshal(e.Content, &ipnetrec)
		asset = &ipnetrec
	case string(oam.Location):
		var location contact.Location

		err = json.Unmarshal(e.Content, &location)
		asset = &location
	case string(oam.Netblock):
		var netblock network.Netblock

		err = json.Unmarshal(e.Content, &netblock)
		asset = &netblock
	case string(oam.Organization):
		var organization org.Organization

		err = json.Unmarshal(e.Content, &organization)
		asset = &organization
	case string(oam.Person):
		var person people.Person

		err = json.Unmarshal(e.Content, &person)
		asset = &person
	case string(oam.Phone):
		var phone contact.Phone

		err = json.Unmarshal(e.Content, &phone)
		asset = &phone
	case string(oam.Product):
		var p platform.Product

		err = json.Unmarshal(e.Content, &p)
		asset = &p
	case string(oam.ProductRelease):
		var pr platform.ProductRelease

		err = json.Unmarshal(e.Content, &pr)
		asset = &pr
	case string(oam.Service):
		var serv platform.Service

		err = json.Unmarshal(e.Content, &serv)
		asset = &serv
	case string(oam.TLSCertificate):
		var tlsCertificate oamtls.TLSCertificate

		err = json.Unmarshal(e.Content, &tlsCertificate)
		asset = &tlsCertificate
	case string(oam.URL):
		var url url.URL

		err = json.Unmarshal(e.Content, &url)
		asset = &url
	default:
		return nil, fmt.Errorf("unknown asset type: %s", e.Type)
	}

	return asset, err
}

// JSONQuery generates a JSON query expression based on the entity's content.
// It returns the generated JSON query expression and an error, if any.
func (e *Entity) JSONQuery() (*datatypes.JSONQueryExpression, error) {
	asset, err := e.Parse()
	if err != nil {
		return nil, err
	}

	jsonQuery := datatypes.JSONQuery("content")
	switch v := asset.(type) {
	case *account.Account:
		return jsonQuery.Equals(v.ID, "unique_id"), nil
	case *oamreg.AutnumRecord:
		return jsonQuery.Equals(v.Handle, "handle"), nil
	case *network.AutonomousSystem:
		return jsonQuery.Equals(v.Number, "number"), nil
	case *contact.ContactRecord:
		return jsonQuery.Equals(v.DiscoveredAt, "discovered_at"), nil
	case *oamreg.DomainRecord:
		return jsonQuery.Equals(v.Domain, "domain"), nil
	case *oamfile.File:
		return jsonQuery.Equals(v.URL, "url"), nil
	case *dns.FQDN:
		return jsonQuery.Equals(v.Name, "name"), nil
	case *financial.FundsTransfer:
		return jsonQuery.Equals(v.ID, "unique_id"), nil
	case *general.Identifier:
		return jsonQuery.Equals(v.ID, "id"), nil
	case *network.IPAddress:
		return jsonQuery.Equals(v.Address.String(), "address"), nil
	case *oamreg.IPNetRecord:
		return jsonQuery.Equals(v.Handle, "handle"), nil
	case *contact.Location:
		return jsonQuery.Equals(v.Address, "address"), nil
	case *network.Netblock:
		return jsonQuery.Equals(v.CIDR.String(), "cidr"), nil
	case *org.Organization:
		return jsonQuery.Equals(v.ID, "unique_id"), nil
	case *people.Person:
		return jsonQuery.Equals(v.FullName, "full_name"), nil
	case *contact.Phone:
		return jsonQuery.Equals(v.Raw, "raw"), nil
	case *platform.Product:
		return jsonQuery.Equals(v.ID, "unique_id"), nil
	case *platform.ProductRelease:
		return jsonQuery.Equals(v.Name, "name"), nil
	case *platform.Service:
		return jsonQuery.Equals(v.ID, "unique_id"), nil
	case *oamtls.TLSCertificate:
		return jsonQuery.Equals(v.SerialNumber, "serial_number"), nil
	case *url.URL:
		return jsonQuery.Equals(v.Raw, "url"), nil
	}

	return nil, fmt.Errorf("unknown asset type: %s", e.Type)
}

// Parse parses the content of the edge into the corresponding Open Asset Model (OAM) relation type.
// It returns the parsed relation and an error, if any.
func (e *Edge) Parse() (oam.Relation, error) {
	var err error
	var rel oam.Relation

	switch e.Type {
	case string(oam.BasicDNSRelation):
		var bdr dns.BasicDNSRelation

		err = json.Unmarshal(e.Content, &bdr)
		rel = &bdr
	case string(oam.PortRelation):
		var pr general.PortRelation

		err = json.Unmarshal(e.Content, &pr)
		rel = &pr
	case string(oam.PrefDNSRelation):
		var pdr dns.PrefDNSRelation

		err = json.Unmarshal(e.Content, &pdr)
		rel = &pdr
	case string(oam.SimpleRelation):
		var sr general.SimpleRelation

		err = json.Unmarshal(e.Content, &sr)
		rel = &sr
	case string(oam.SRVDNSRelation):
		var sdr dns.SRVDNSRelation

		err = json.Unmarshal(e.Content, &sdr)
		rel = &sdr
	default:
		return nil, fmt.Errorf("unknown relation type: %s", e.Type)
	}

	return rel, err
}

// Parse parses the content of the entity tag into the corresponding Open Asset Model (OAM) property type.
// It returns the parsed property and an error, if any.
func (e *EntityTag) Parse() (oam.Property, error) {
	return parseProperty(e.Type, e.Content)
}

// Parse parses the content of the edge tag into the corresponding Open Asset Model (OAM) property type.
// It returns the parsed property and an error, if any.
func (e *EdgeTag) Parse() (oam.Property, error) {
	return parseProperty(e.Type, e.Content)
}

func parseProperty(ptype string, content datatypes.JSON) (oam.Property, error) {
	var err error
	var prop oam.Property

	switch ptype {
	case string(oam.DNSRecordProperty):
		var dp dns.DNSRecordProperty

		err = json.Unmarshal(content, &dp)
		prop = &dp
	case string(oam.SimpleProperty):
		var sp general.SimpleProperty

		err = json.Unmarshal(content, &sp)
		prop = &sp
	case string(oam.SourceProperty):
		var sp general.SourceProperty

		err = json.Unmarshal(content, &sp)
		prop = &sp
	case string(oam.VulnProperty):
		var vp platform.VulnProperty

		err = json.Unmarshal(content, &vp)
		prop = &vp
	default:
		return nil, fmt.Errorf("unknown property type: %s", ptype)
	}

	return prop, err
}

// NameJSONQuery generates the JSON query for the field returned by the Property Name method.
// It returns the parsed property and an error, if any.
func (e *EntityTag) NameJSONQuery() (*datatypes.JSONQueryExpression, error) {
	prop, err := e.Parse()
	if err != nil {
		return nil, err
	}

	return propertyNameJSONQuery(prop)
}

// NameJSONQuery generates the JSON query for the field returned by the Property Name method.
// It returns the parsed property and an error, if any.
func (e *EdgeTag) NameJSONQuery() (*datatypes.JSONQueryExpression, error) {
	prop, err := e.Parse()
	if err != nil {
		return nil, err
	}

	return propertyNameJSONQuery(prop)
}

func propertyNameJSONQuery(prop oam.Property) (*datatypes.JSONQueryExpression, error) {
	jsonQuery := datatypes.JSONQuery("content")

	switch v := prop.(type) {
	case *dns.DNSRecordProperty:
		return jsonQuery.Equals(v.PropertyName, "property_name"), nil
	case *general.SimpleProperty:
		return jsonQuery.Equals(v.PropertyName, "property_name"), nil
	case *general.SourceProperty:
		return jsonQuery.Equals(v.Source, "name"), nil
	case *platform.VulnProperty:
		return jsonQuery.Equals(v.ID, "id"), nil
	}

	return nil, fmt.Errorf("unknown property type: %s", prop.PropertyType())
}

// ValueJSONQuery generates the JSON query for the field returned by the Property Value method.
// It returns the parsed property and an error, if any.
func (e *EntityTag) ValueJSONQuery() (*datatypes.JSONQueryExpression, error) {
	prop, err := e.Parse()
	if err != nil {
		return nil, err
	}

	return propertyValueJSONQuery(prop)
}

// ValueJSONQuery generates the JSON query for the field returned by the Property Value method.
// It returns the parsed property and an error, if any.
func (e *EdgeTag) ValueJSONQuery() (*datatypes.JSONQueryExpression, error) {
	prop, err := e.Parse()
	if err != nil {
		return nil, err
	}

	return propertyValueJSONQuery(prop)
}

func propertyValueJSONQuery(prop oam.Property) (*datatypes.JSONQueryExpression, error) {
	jsonQuery := datatypes.JSONQuery("content")

	switch v := prop.(type) {
	case *dns.DNSRecordProperty:
		return jsonQuery.Equals(v.Data, "data"), nil
	case *general.SimpleProperty:
		return jsonQuery.Equals(v.PropertyValue, "property_value"), nil
	case *general.SourceProperty:
		return jsonQuery.Equals(v.Confidence, "confidence"), nil
	case *platform.VulnProperty:
		return jsonQuery.Equals(v.Description, "desc"), nil
	}

	return nil, fmt.Errorf("unknown property type: %s", prop.PropertyType())
}
