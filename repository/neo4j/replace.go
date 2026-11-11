// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// ReplaceAsset implements the AssetReplacer interface: it stores the
// asset's content exactly, clearing the fields it leaves empty. Updating
// an existing node already replaces all of its properties.
func (neo *NeoRepository) ReplaceAsset(ctx context.Context, asset oam.Asset) (*types.Entity, error) {
	o, ok := asset.(*oamorg.Organization)
	if !ok || o == nil {
		return nil, fmt.Errorf("replacing a %T is not supported", asset)
	}
	if o.ID == "" || o.Name == "" {
		return nil, errors.New("the organization ID and name are required")
	}

	ents, err := neo.FindEntitiesByContent(ctx, oam.Organization, time.Time{}, 1,
		types.ContentFilters{"unique_id": o.ID})
	if err != nil || len(ents) == 0 {
		return nil, fmt.Errorf("no organization %q to replace", o.ID)
	}

	return neo.CreateEntity(ctx, &types.Entity{ID: ents[0].ID, CreatedAt: ents[0].CreatedAt, Asset: o})
}
