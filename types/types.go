// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	oam "github.com/owasp-amass/open-asset-model"
)

// Entity represents an entity in the asset database.
type Entity struct {
	ID        string
	CreatedAt time.Time
	LastSeen  time.Time
	Asset     oam.Asset
}

// EntityTag represents additional metadata added to an entity in the asset database.
type EntityTag struct {
	ID        string
	CreatedAt time.Time
	LastSeen  time.Time
	Property  oam.Property
	Entity    *Entity
}

// Edge represents a relationship between two entities in the asset database.
type Edge struct {
	ID         string
	CreatedAt  time.Time
	LastSeen   time.Time
	Relation   oam.Relation
	FromEntity *Entity
	ToEntity   *Entity
}

// EdgeTag represents additional metadata added to an edge in the asset database.
type EdgeTag struct {
	ID        string
	CreatedAt time.Time
	LastSeen  time.Time
	Property  oam.Property
	Edge      *Edge
}
