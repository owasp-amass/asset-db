//go:build integration

// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
)

func TestCreateEntity(t *testing.T) {
	entity, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "test.com",
		},
	})
	if err != nil {
		t.Errorf("Failed to create the entity: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	newer, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "test.com",
		},
	})
	if err != nil {
		t.Errorf("Failed to create the newer entity: %v", err)
	}
	if entity.ID != newer.ID || entity.Asset.AssetType() != newer.Asset.AssetType() {
		t.Errorf("Failed to prevent duplicate entities from being created")
	}
	if fqdn1, ok := entity.Asset.(*domain.FQDN); !ok {
		t.Errorf("Failed to type assert the first asset")
	} else if fqdn2, ok := newer.Asset.(*domain.FQDN); !ok {
		t.Errorf("Failed to type assert the second asset")
	} else if fqdn1.Name != fqdn2.Name {
		t.Errorf("Failed to keep the asset the same")
	}
	if !entity.CreatedAt.Equal(newer.CreatedAt) {
		t.Errorf("Failed to keep the CreatedAt timestamp the same")
	}
	if !entity.LastSeen.Before(newer.LastSeen) {
		t.Errorf("Failed to update the LastSeen timestamp")
	}
}
