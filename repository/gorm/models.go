package gorm

import (
	"encoding/json"
	"fmt"
	"time"

	open_asset_model "github.com/owasp-amass/asset-db/open_asset_model"
	"github.com/owasp-amass/asset-db/types"

	"gorm.io/datatypes"
)

type Asset struct {
	ID        int64     `gorm:"primaryKey;autoIncrement:true"`
	CreatedAt time.Time `gorm:"type:datetime"`
	Type      string
	Content   datatypes.JSON
}

func (a Asset) Parse() (types.Asset, error) {
	var asset types.Asset
	// TODO: should transform a.Type to AssetType ?
	switch a.Type {
	case string(types.FQDN):
		var fqdn open_asset_model.FQDN
		err := json.Unmarshal(a.Content, &fqdn)
		if err != nil {
			return open_asset_model.FQDN{}, err
		}
		asset = fqdn
	case string(types.IPAddress):
		var ip open_asset_model.IPAddress
		err := json.Unmarshal(a.Content, &ip)
		if err != nil {
			return open_asset_model.IPAddress{}, err
		}
		asset = ip
	case string(types.AutonomousSystem):
		var asn open_asset_model.AutonomousSystem
		err := json.Unmarshal(a.Content, &asn)
		if err != nil {
			return open_asset_model.AutonomousSystem{}, err
		}
		asset = asn
	case string(types.RIROrganization):
		var rir open_asset_model.RIROrganization
		err := json.Unmarshal(a.Content, &rir)
		if err != nil {
			return open_asset_model.RIROrganization{}, err
		}
		asset = rir
	case string(types.Netblock):
		var netblock open_asset_model.Netblock
		err := json.Unmarshal(a.Content, &netblock)
		if err != nil {
			return open_asset_model.Netblock{}, err
		}
		asset = netblock
	default:
		return nil, fmt.Errorf("unknown asset type: %s", a.Type)
	}

	return asset, nil
}

func (a Asset) GetJSONQuery() (*datatypes.JSONQueryExpression, error) {
	switch a.Type {
	case string(types.FQDN):
		asset, err := a.Parse()
		if err != nil {
			return nil, err
		}
		assetData := asset.(open_asset_model.FQDN)
		return datatypes.JSONQuery("content").Equals(assetData.Name, "name").Equals(assetData.Name, "name2"), nil
	default:
		return nil, fmt.Errorf("unknown asset type: %s", a.Type)
	}
}

type Relation struct {
	ID          int64     `gorm:"primaryKey;autoIncrement:true"`
	CreatedAt   time.Time `gorm:"type:datetime"`
	Type        string
	FromAssetID int64
	ToAssetID   int64
	FromAsset   Asset
	ToAsset     Asset
}
