// Package types provides types that represent models in databases but are not tied to a specific database implementation.
package types

import (
	oam "github.com/owasp-amass/open-asset-model"
)

// Asset represents an asset in the asset database.
// It contains an ID and the corresponding oam.Asset.
type Asset struct {
	ID    string    // The unique identifier of the asset.
	Asset oam.Asset // The actual asset data.
}

// Relation represents a relationship between two assets in the asset database.
// It contains an ID, a type describing the relationship, and references to the source and destination assets.
type Relation struct {
	ID        string // The unique identifier of the relation.
	Type      string // The type of the relationship.
	FromAsset *Asset // The source asset of the relation.
	ToAsset   *Asset // The destination asset of the relation.
}
