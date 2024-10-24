// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	oam "github.com/owasp-amass/open-asset-model"
)

// Entity represents an entity in the asset database.
// It contains an ID and the corresponding oam.Asset.
type Entity struct {
	ID        string
	CreatedAt time.Time
	LastSeen  time.Time
	Asset     oam.Asset
}

// Relation represents a relationship between two entities in the asset database.
// It contains an ID, a type describing the relationship, and references to the source and destination entities.
type Relation struct {
	ID         string
	Type       string
	CreatedAt  time.Time
	LastSeen   time.Time
	FromEntity *Entity
	ToEntity   *Entity
}
