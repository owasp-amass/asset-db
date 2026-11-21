// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

// CoKey identifies a blocking key by which two entities of the same type can be
// grouped as duplicate candidates in the database, without loading the whole
// type into memory. It backs repository.CoKeyedGroups.
type CoKey int

const (
	// CoKeyIdentifier groups source entities that point at the same Identifier
	// entity through an outgoing edge labeled "id". Identifiers are de-duplicated
	// by their unique_id, so two entities sharing an identifier value reference
	// the same Identifier node; no value normalization is needed.
	CoKeyIdentifier CoKey = iota
	// CoKeyContactRecord groups source entities named by the same ContactRecord
	// through an incoming edge labeled "organization".
	CoKeyContactRecord
	// CoKeyRegistration groups source entities (organizations) sharing a
	// normalized (jurisdiction, registration_id): jurisdiction upper-cased and
	// trimmed, registration_id upper-cased with whitespace removed, both present.
	CoKeyRegistration
	// CoKeyTag groups source entities sharing a (property_name, property_value)
	// entity tag. The property name is the CoKeyedGroups param (e.g. brand_key).
	CoKeyTag
	// CoKeyStreetAddress groups source entities that point at the same
	// StreetAddress entity through an outgoing edge labeled legal_address,
	// hq_address or street_address. It groups by shared StreetAddress node, so it is
	// exact when addresses are de-duplicated and otherwise misses two entities
	// at the same address held as separate StreetAddress nodes.
	CoKeyStreetAddress
)

// CoKeyGroup is a set of at least two entity ids of one asset type that share a
// blocking key value.
type CoKeyGroup struct {
	// Key is the shared key value (diagnostic): the identifier/contact entity id,
	// the "jurisdiction|registration" pair, or the tag value.
	Key string
	// IDs are the entity ids (asset ids) that share the key.
	IDs []string
}
