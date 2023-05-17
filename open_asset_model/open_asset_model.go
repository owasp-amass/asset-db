package open_asset_model

import (
	"encoding/json"
	"net"

	"github.com/owasp-amass/asset-db/types"
)

type FQDN struct {
	Name string `json:"name"`
}

func (f FQDN) AssetType() types.AssetType {
	return types.FQDN
}

func (f FQDN) JSON() ([]byte, error) {
	return json.Marshal(f)
}

type AutonomousSystem struct {
	Number int `json:"number"`
}

func (as AutonomousSystem) AssetType() types.AssetType {
	return types.AutonomousSystem
}

func (as AutonomousSystem) JSON() ([]byte, error) {
	return json.Marshal(as)
}

type RIROrganization struct {
	Name  string `json:"name"`
	RIRId string `json:"rir_id"`
	RIR   string `json:"rir"`
}

func (riro RIROrganization) AssetType() types.AssetType {
	return types.RIROrganization
}

func (riro RIROrganization) JSON() ([]byte, error) {
	return json.Marshal(riro)
}

type IPAddress struct {
	Address net.IP `json:"address"`
	Type    string `json:"type"`
}

func (ipa IPAddress) AssetType() types.AssetType {
	return types.IPAddress
}

func (ipa IPAddress) JSON() ([]byte, error) {
	return json.Marshal(ipa)
}

type Netblock struct {
	Cidr string `json:"cidr"`
	Type string `json:"type"`
}

func (nb Netblock) AssetType() types.AssetType {
	return types.Netblock
}

func (nb Netblock) JSON() ([]byte, error) {
	return json.Marshal(nb)
}
