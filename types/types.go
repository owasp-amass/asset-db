package types

type AssetType string

const (
	FQDN             AssetType = "FQDN"
	AutonomousSystem AssetType = "ASN"
	RIROrganization  AssetType = "RIROrg"
	IPAddress        AssetType = "IPAddress"
	Netblock         AssetType = "Netblock"
)

type Asset interface {
	AssetType() AssetType
	JSON() ([]byte, error)
}

type StoredAsset struct {
	ID    string
	Asset Asset
}

type StoredRelation struct {
	ID          string
	Type        string
	FromAssetID string
	ToAssetID   string
}
