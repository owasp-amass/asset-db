// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"encoding/json"
	"fmt"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	oamtls "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	"github.com/owasp-amass/open-asset-model/fingerprint"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/service"
	"github.com/owasp-amass/open-asset-model/source"
	"github.com/owasp-amass/open-asset-model/url"
	"gorm.io/datatypes"
)

// Entity represents an entity stored in the database.
type Entity struct {
	ID        uint64    `gorm:"primaryKey;column:entity_id"`
	CreatedAt time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column:created_at"`
	LastSeen  time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column:last_seen"`
	Type      string    `gorm:"column:etype"`
	Content   datatypes.JSON
}

// Relation represents a relationship between two entities stored in the database.
type Relation struct {
	ID           uint64    `gorm:"primaryKey;column:relation_id"`
	CreatedAt    time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();"`
	LastSeen     time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();"`
	Type         string    `gorm:"column:rtype"`
	Content      datatypes.JSON
	FromEntityID uint64 `gorm:"column:from_entity_id"`
	ToEntityID   uint64 `gorm:"column:to_entity_id"`
	FromEntity   Entity
	ToEntity     Entity
}

// Parse parses the content of the entity into the corresponding Open Asset Model (OAM) asset type.
// It returns the parsed asset and an error, if any.
func (e *Entity) Parse() (oam.Asset, error) {
	var err error
	var asset oam.Asset

	switch e.Type {
	case string(oam.FQDN):
		var fqdn domain.FQDN

		err = json.Unmarshal(e.Content, &fqdn)
		asset = &fqdn
	case string(oam.NetworkEndpoint):
		var ne domain.NetworkEndpoint

		err = json.Unmarshal(e.Content, &ne)
		asset = &ne
	case string(oam.IPAddress):
		var ip network.IPAddress

		err = json.Unmarshal(e.Content, &ip)
		asset = &ip
	case string(oam.AutonomousSystem):
		var as network.AutonomousSystem

		err = json.Unmarshal(e.Content, &as)
		asset = &as
	case string(oam.AutnumRecord):
		var ar oamreg.AutnumRecord

		err = json.Unmarshal(e.Content, &ar)
		asset = &ar
	case string(oam.Netblock):
		var netblock network.Netblock

		err = json.Unmarshal(e.Content, &netblock)
		asset = &netblock
	case string(oam.IPNetRecord):
		var ipnetrec oamreg.IPNetRecord

		err = json.Unmarshal(e.Content, &ipnetrec)
		asset = &ipnetrec
	case string(oam.SocketAddress):
		var sa network.SocketAddress

		err = json.Unmarshal(e.Content, &sa)
		asset = &sa
	case string(oam.DomainRecord):
		var dr oamreg.DomainRecord

		err = json.Unmarshal(e.Content, &dr)
		asset = &dr
	case string(oam.Fingerprint):
		var fingerprint fingerprint.Fingerprint

		err = json.Unmarshal(e.Content, &fingerprint)
		asset = &fingerprint
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
	case string(oam.EmailAddress):
		var emailAddress contact.EmailAddress

		err = json.Unmarshal(e.Content, &emailAddress)
		asset = &emailAddress
	case string(oam.Location):
		var location contact.Location

		err = json.Unmarshal(e.Content, &location)
		asset = &location
	case string(oam.ContactRecord):
		var cr contact.ContactRecord

		err = json.Unmarshal(e.Content, &cr)
		asset = &cr
	case string(oam.TLSCertificate):
		var tlsCertificate oamtls.TLSCertificate

		err = json.Unmarshal(e.Content, &tlsCertificate)
		asset = &tlsCertificate
	case string(oam.URL):
		var url url.URL

		err = json.Unmarshal(e.Content, &url)
		asset = &url
	case string(oam.Source):
		var src source.Source

		err = json.Unmarshal(e.Content, &src)
		asset = &src
	case string(oam.Service):
		var serv service.Service

		err = json.Unmarshal(e.Content, &serv)
		asset = &serv
	case string(oam.File):
		var f oamfile.File

		err = json.Unmarshal(e.Content, &f)
		asset = &f
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
	case *domain.FQDN:
		return jsonQuery.Equals(v.Name, "name"), nil
	case *domain.NetworkEndpoint:
		return jsonQuery.Equals(v.Address, "address"), nil
	case *network.SocketAddress:
		return jsonQuery.Equals(v.Address.String(), "address"), nil
	case *network.IPAddress:
		return jsonQuery.Equals(v.Address.String(), "address"), nil
	case *network.AutonomousSystem:
		return jsonQuery.Equals(v.Number, "number"), nil
	case *network.Netblock:
		return jsonQuery.Equals(v.CIDR.String(), "cidr"), nil
	case *oamreg.IPNetRecord:
		return jsonQuery.Equals(v.Handle, "handle"), nil
	case *oamreg.AutnumRecord:
		return jsonQuery.Equals(v.Handle, "handle"), nil
	case *oamreg.DomainRecord:
		return jsonQuery.Equals(v.Domain, "domain"), nil
	case *fingerprint.Fingerprint:
		return jsonQuery.Equals(v.Value, "value"), nil
	case *org.Organization:
		return jsonQuery.Equals(v.Name, "name"), nil
	case *people.Person:
		return jsonQuery.Equals(v.FullName, "full_name"), nil
	case *contact.Phone:
		return jsonQuery.Equals(v.Raw, "raw"), nil
	case *contact.EmailAddress:
		return jsonQuery.Equals(v.Address, "address"), nil
	case *contact.Location:
		return jsonQuery.Equals(v.Address, "address"), nil
	case *contact.ContactRecord:
		return jsonQuery.Equals(v.DiscoveredAt, "discovered_at"), nil
	case *oamtls.TLSCertificate:
		return jsonQuery.Equals(v.SerialNumber, "serial_number"), nil
	case *url.URL:
		return jsonQuery.Equals(v.Raw, "url"), nil
	case *source.Source:
		return jsonQuery.Equals(v.Name, "name"), nil
	case *service.Service:
		return jsonQuery.Equals(v.Identifier, "identifier"), nil
	case *oamfile.File:
		return jsonQuery.Equals(v.URL, "url"), nil
	}

	return nil, fmt.Errorf("unknown asset type: %s", e.Type)
}
