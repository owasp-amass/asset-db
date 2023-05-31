package repository

import (
	"encoding/json"
	"fmt"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"

	"gorm.io/datatypes"
)

// Asset represents an asset stored in the database.
type Asset struct {
	ID        int64          `gorm:"primaryKey;autoIncrement:true"` // The unique identifier of the asset.
	CreatedAt time.Time      `gorm:"type:datetime"`                 // The creation timestamp of the asset.
	Type      string         // The type of the asset.
	Content   datatypes.JSON // The JSON-encoded content of the asset.
}

// Parse parses the content of the asset into the corresponding Open Asset Model (OAM) asset type.
// It returns the parsed asset and an error, if any.
func (a Asset) Parse() (oam.Asset, error) {
	var asset oam.Asset
	switch a.Type {
	case string(oam.FQDN):
		var fqdn domain.FQDN
		err := json.Unmarshal(a.Content, &fqdn)
		if err != nil {
			return domain.FQDN{}, err
		}
		asset = fqdn
	case string(oam.IPAddress):
		var ip network.IPAddress
		err := json.Unmarshal(a.Content, &ip)
		if err != nil {
			return network.IPAddress{}, err
		}
		asset = ip
	case string(oam.ASN):
		var asn network.AutonomousSystem
		err := json.Unmarshal(a.Content, &asn)
		if err != nil {
			return network.AutonomousSystem{}, err
		}
		asset = asn
	case string(oam.RIROrg):
		var rir network.RIROrganization
		err := json.Unmarshal(a.Content, &rir)
		if err != nil {
			return network.RIROrganization{}, err
		}
		asset = rir
	case string(oam.Netblock):
		var netblock network.Netblock
		err := json.Unmarshal(a.Content, &netblock)
		if err != nil {
			return network.Netblock{}, err
		}
		asset = netblock
	default:
		return nil, fmt.Errorf("unknown asset type: %s", a.Type)
	}

	return asset, nil
}

// JSONQuery generates a JSON query expression based on the asset's content.
// It returns the generated JSON query expression and an error, if any.
func (a Asset) JSONQuery() (*datatypes.JSONQueryExpression, error) {
	asset, err := a.Parse()
	if err != nil {
		return nil, err
	}

	jsonQuery := datatypes.JSONQuery("content")
	switch a.Type {
	case string(oam.FQDN):
		assetData := asset.(domain.FQDN)
		return jsonQuery.Equals(assetData.Name, "name"), nil
	case string(oam.IPAddress):
		assetData := asset.(network.IPAddress)
		return jsonQuery.Equals(assetData.Address.String(), "address"), nil
	case string(oam.ASN):
		assetData := asset.(network.AutonomousSystem)
		return jsonQuery.Equals(assetData.Number, "number"), nil
	case string(oam.Netblock):
		assetData := asset.(network.Netblock)
		return jsonQuery.Equals(assetData.Cidr.String(), "cidr"), nil
	case string(oam.RIROrg):
		assetData := asset.(network.RIROrganization)
		return jsonQuery.Equals(assetData.Name, "name"), nil
	default:
		return nil, fmt.Errorf("unknown asset type: %s", a.Type)
	}
}

// Relation represents a relationship between two assets stored in the database.
type Relation struct {
	ID          int64     `gorm:"primaryKey;autoIncrement:true"` // The unique identifier of the relation.
	CreatedAt   time.Time `gorm:"type:datetime"`                 // The creation timestamp of the relation.
	Type        string    // The type of the relation.
	FromAssetID int64     // The ID of the asset from which the relation originates.
	ToAssetID   int64     // The ID of the asset to which the relation points.
	FromAsset   Asset     // The asset from which the relation originates.
	ToAsset     Asset     // The asset to which the relation points.
}
