// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// GraphChanges is what changed in the graph since a time, as a reader that
// keeps what it read needs to know to keep it current.
type GraphChanges struct {
	// Now is the time the changes were read, by the clock the store's
	// writes use. Pass it back as the next since.
	Now time.Time `json:"now"`
	// Deletions counts every deletion the store has made: of an entity, an
	// edge or a tag. A reader that saw a smaller count has read something
	// that is gone.
	Deletions int64 `json:"deletions"`
	// EntityIDs are the entities created or updated since then, the two
	// ends of each edge created or updated since then, and the entities
	// whose tags, or whose edges' tags, were. Empty when since is zero.
	EntityIDs []string `json:"entity_ids,omitempty"`
}
