package repository

import (
	"encoding/json"
	"fmt"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/fingerprint"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	oamtls "github.com/owasp-amass/open-asset-model/tls_certificates"
	"github.com/owasp-amass/open-asset-model/url"
	"github.com/owasp-amass/open-asset-model/whois"

	"gorm.io/datatypes"
)

// Asset represents an asset stored in the database.
type Asset struct {
	ID        uint64         `gorm:"primaryKey;autoIncrement:true"`                               // The unique identifier of the asset.
	CreatedAt time.Time      `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column=created_at"` // The creation timestamp of the asset.
	LastSeen  time.Time      `gorm:"type:datetime;default:CURRENT_TIMESTAMP();column=last_seen"`  // The last seen timestamp of the asset.
	Type      string         // The type of the asset.
	Content   datatypes.JSON // The JSON-encoded content of the asset.
}

// Relation represents a relationship between two assets stored in the database.
type Relation struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement:true"`              // The unique identifier of the relation.
	CreatedAt   time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();"` // The creation timestamp of the relation.
	LastSeen    time.Time `gorm:"type:datetime;default:CURRENT_TIMESTAMP();"` // The last seen timestamp of the relation.
	Type        string    // The type of the relation.
	FromAssetID uint64    // The ID of the asset from which the relation originates.
	ToAssetID   uint64    // The ID of the asset to which the relation points.
	FromAsset   Asset     // The asset from which the relation originates.
	ToAsset     Asset     // The asset to which the relation points.
}

// Parse parses the content of the asset into the corresponding Open Asset Model (OAM) asset type.
// It returns the parsed asset and an error, if any.
func (a *Asset) Parse() (oam.Asset, error) {
	var err error
	var asset oam.Asset

	switch a.Type {
	case string(oam.FQDN):
		var fqdn domain.FQDN

		err = json.Unmarshal(a.Content, &fqdn)
		asset = &fqdn
	case string(oam.IPAddress):
		var ip network.IPAddress

		err = json.Unmarshal(a.Content, &ip)
		asset = &ip
	case string(oam.ASN):
		var asn network.AutonomousSystem

		err = json.Unmarshal(a.Content, &asn)
		asset = &asn
	case string(oam.RIROrg):
		var rir network.RIROrganization

		err = json.Unmarshal(a.Content, &rir)
		asset = &rir
	case string(oam.Netblock):
		var netblock network.Netblock

		err = json.Unmarshal(a.Content, &netblock)
		asset = &netblock
	case string(oam.Port):
		var port network.Port

		err = json.Unmarshal(a.Content, &port)
		asset = &port
	case string(oam.WHOIS):
		var whois whois.WHOIS

		err = json.Unmarshal(a.Content, &whois)
		asset = &whois
	case string(oam.Registrar):
		var registrar whois.Registrar

		err = json.Unmarshal(a.Content, &registrar)
		asset = &registrar
	case string(oam.Fingerprint):
		var fingerprint fingerprint.Fingerprint

		err = json.Unmarshal(a.Content, &fingerprint)
		asset = &fingerprint
	case string(oam.Organization):
		var organization org.Organization

		err = json.Unmarshal(a.Content, &organization)
		asset = &organization
	case string(oam.Person):
		var person people.Person

		err = json.Unmarshal(a.Content, &person)
		asset = &person
	case string(oam.Phone):
		var phone contact.Phone

		err = json.Unmarshal(a.Content, &phone)
		asset = &phone
	case string(oam.Email):
		var emailAddress contact.EmailAddress

		err = json.Unmarshal(a.Content, &emailAddress)
		asset = &emailAddress
	case string(oam.Location):
		var location contact.Location

		err = json.Unmarshal(a.Content, &location)
		asset = &location
	case string(oam.TLSCertificate):
		var tlsCertificate oamtls.TLSCertificate

		err = json.Unmarshal(a.Content, &tlsCertificate)
		asset = &tlsCertificate
	case string(oam.URL):
		var url url.URL

		err = json.Unmarshal(a.Content, &url)
		asset = &url
	default:
		return nil, fmt.Errorf("unknown asset type: %s", a.Type)
	}

	return asset, err
}

// JSONQuery generates a JSON query expression based on the asset's content.
// It returns the generated JSON query expression and an error, if any.
func (a *Asset) JSONQuery() (*datatypes.JSONQueryExpression, error) {
	asset, err := a.Parse()
	if err != nil {
		return nil, err
	}

	jsonQuery := datatypes.JSONQuery("content")
	switch v := asset.(type) {
	case *domain.FQDN:
		return jsonQuery.Equals(v.Name, "name"), nil
	case *network.Port:
		return jsonQuery.Equals(v.Number, "number"), nil
	case *network.IPAddress:
		return jsonQuery.Equals(v.Address.String(), "address"), nil
	case *network.AutonomousSystem:
		return jsonQuery.Equals(v.Number, "number"), nil
	case *network.Netblock:
		return jsonQuery.Equals(v.Cidr.String(), "cidr"), nil
	case *network.RIROrganization:
		return jsonQuery.Equals(v.Name, "name"), nil
	case *whois.WHOIS:
		return jsonQuery.Equals(v.Domain, "domain"), nil
	case *whois.Registrar:
		return jsonQuery.Equals(v.Name, "name"), nil
	case *fingerprint.Fingerprint:
		return jsonQuery.Equals(v.Value, "value"), nil
	case *org.Organization:
		return jsonQuery.Equals(v.OrgName, "org_name"), nil
	case *people.Person:
		return jsonQuery.Equals(v.FullName, "full_name"), nil
	case *contact.Phone:
		return jsonQuery.Equals(v.Raw, "raw"), nil
	case *contact.EmailAddress:
		return jsonQuery.Equals(v.Address, "address"), nil
	case *contact.Location:
		return jsonQuery.Equals(v.FormattedAddress, "formatted_address"), nil
	case *oamtls.TLSCertificate:
		return jsonQuery.Equals(v.SerialNumber, "serial_number"), nil
	case *url.URL:
		return jsonQuery.Equals(v.Raw, "url"), nil
	}

	return nil, fmt.Errorf("unknown asset type: %s", a.Type)
}
