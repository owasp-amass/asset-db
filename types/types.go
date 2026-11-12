// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	oam "github.com/owasp-amass/open-asset-model"
)

type ContentFilters map[string]any

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

// EdgeCursor marks the last edge of a page read by a repository's
// ReadEdgesPage. Pages run newest first: updated_at descending, then edge
// ID descending.
type EdgeCursor struct {
	UpdatedAt time.Time
	EdgeID    string
	// SortKey is updated_at exactly as the repository compared it. SQLite
	// stores it as text in more than one format, so a cursor is passed back
	// unchanged rather than rebuilt from UpdatedAt.
	SortKey string
}
