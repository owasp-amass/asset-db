// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"

	model "github.com/owasp-amass/open-asset-model"
)

const CachePropertyType model.PropertyType = "CacheProperty"

// CacheProperty represents a cache property in the cached graph.
type CacheProperty struct {
	ID        string `json:"cache_id"`
	RefID     string `json:"ref_id"`
	Timestamp string `json:"timestamp"`
}

// Name implements the Property interface.
func (p CacheProperty) Name() string {
	return p.ID
}

// Value implements the Property interface.
func (p CacheProperty) Value() string {
	return p.RefID
}

// PropertyType implements the Property interface.
func (p CacheProperty) PropertyType() model.PropertyType {
	return CachePropertyType
}

// JSON implements the Property interface.
func (p CacheProperty) JSON() ([]byte, error) {
	return json.Marshal(p)
}
