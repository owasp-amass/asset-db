//go:build integration

// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/stretchr/testify/assert"
)

func TestCreateEntity(t *testing.T) {
	entity, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "create1.entity",
		},
	})
	assert.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	newer, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "create1.entity",
		},
	})
	assert.NoError(t, err)

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

	assert.Equal(t, entity.CreatedAt, newer.CreatedAt)
	if !entity.LastSeen.Before(newer.LastSeen) {
		t.Errorf("Failed to update the LastSeen timestamp")
	}

	time.Sleep(250 * time.Millisecond)
	second, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "create2.entity",
		},
	})
	assert.NoError(t, err)

	assert.NotEqual(t, entity.ID, second.ID)
	if !second.CreatedAt.After(newer.LastSeen) {
		t.Errorf("Failed to assign the second entity an accurate creation time")
	}
}

func TestFindEntityById(t *testing.T) {
	entity, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "find1.entity",
		},
	})
	assert.NoError(t, err)

	same, err := store.FindEntityById(entity.ID)
	assert.NoError(t, err)
	assert.Equal(t, entity.ID, same.ID)

	if fqdn1, ok := entity.Asset.(*domain.FQDN); !ok {
		t.Errorf("Failed to type assert the first asset")
	} else if fqdn2, ok := same.Asset.(*domain.FQDN); !ok {
		t.Errorf("Failed to type assert the second asset")
	} else if fqdn1.Name != fqdn2.Name {
		t.Errorf("Failed to return an entity with the correct name")
	}
}

func TestFindEntitiesByContent(t *testing.T) {
	fqdn := &domain.FQDN{Name: "findcontent.entity"}

	_, err := store.FindEntitiesByContent(fqdn, time.Time{})
	assert.Error(t, err)

	entity, err := store.CreateAsset(fqdn)
	assert.NoError(t, err)

	e, err := store.FindEntitiesByContent(fqdn, entity.CreatedAt.Add(-1*time.Second))
	assert.NoError(t, err)
	same := e[0]
	assert.Equal(t, entity.ID, same.ID)

	if fqdn1, ok := entity.Asset.(*domain.FQDN); !ok {
		t.Errorf("Failed to type assert the first asset")
	} else if fqdn2, ok := same.Asset.(*domain.FQDN); !ok {
		t.Errorf("Failed to type assert the second asset")
	} else if fqdn1.Name != fqdn2.Name {
		t.Errorf("Failed to return an entity with the correct name")
	}

	_, err = store.FindEntitiesByContent(fqdn, entity.CreatedAt.Add(250*time.Millisecond))
	assert.Error(t, err)
}

func TestFindEntitiesByType(t *testing.T) {
	now := time.Now()

	for i := 1; i <= 10; i++ {
		addr, err := netip.ParseAddr(fmt.Sprintf("192.168.1.%d", i))
		assert.NoError(t, err)

		_, err = store.CreateAsset(&oamnet.IPAddress{
			Address: addr,
			Type:    "IPv4",
		})
		assert.NoError(t, err)
	}

	entities, err := store.FindEntitiesByType(oam.IPAddress, time.Time{})
	assert.NoError(t, err)

	if len(entities) < 10 {
		t.Errorf("Failed to return the correct number of entities")
	}

	for i := 1; i <= 10; i++ {
		_, err := store.CreateAsset(&org.Organization{Name: fmt.Sprintf("findtype%d.entity", i)})
		assert.NoError(t, err)
	}

	entities, err = store.FindEntitiesByType(oam.Organization, now)
	assert.NoError(t, err)

	if len(entities) < 10 {
		t.Errorf("Failed to return the correct number of entities")
	}
}

func TestDeleteEntity(t *testing.T) {
	entity, err := store.CreateEntity(&types.Entity{
		Asset: &domain.FQDN{
			Name: "delete.entity",
		},
	})
	assert.NoError(t, err)

	err = store.DeleteEntity(entity.ID)
	assert.NoError(t, err)

	_, err = store.FindEntityById(entity.ID)
	assert.Error(t, err)
}
