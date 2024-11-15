// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlrepo

import (
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/property"
	"github.com/owasp-amass/open-asset-model/relation"
	"github.com/stretchr/testify/assert"
)

func TestEntityTag(t *testing.T) {
	entity, err := store.CreateEntity(&domain.FQDN{Name: "utica.edu"})
	assert.NoError(t, err)

	now := time.Now().Truncate(time.Second).UTC()
	prop := &property.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foo",
	}

	ct, err := store.CreateEntityTag(entity, prop)
	assert.NoError(t, err)
	assert.Equal(t, ct.Property.Name(), prop.PropertyName)
	assert.Equal(t, ct.Property.Value(), prop.PropertyValue)
	assert.Equal(t, oam.SimpleProperty, ct.Property.PropertyType())
	if now.After(ct.CreatedAt.UTC()) {
		t.Errorf("tag.CreatedAt: %s, expected to be after: %s", ct.CreatedAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	}
	if now.After(ct.LastSeen.UTC()) {
		t.Errorf("tag.LastSeen: %s, expected to be after: %s", ct.LastSeen.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	}

	tag, err := store.FindEntityTagById(ct.ID)
	assert.NoError(t, err)
	assert.Equal(t, ct.CreatedAt, tag.CreatedAt)
	assert.Equal(t, ct.LastSeen, tag.LastSeen)
	assert.Equal(t, ct.Property.Name(), tag.Property.Name())
	assert.Equal(t, ct.Property.Value(), tag.Property.Value())

	time.Sleep(time.Second)
	ct2, err := store.CreateEntityTag(entity, prop)
	assert.NoError(t, err)
	if ct2.LastSeen.UnixNano() < ct.LastSeen.UnixNano() {
		t.Errorf("ct2.LastSeen: %s, ct.LastSeen: %s", ct2.LastSeen.Format(time.RFC3339Nano), ct.LastSeen.Format(time.RFC3339Nano))
	}

	time.Sleep(time.Second)
	prop.PropertyValue = "bar"
	ct3, err := store.CreateEntityTag(entity, prop)
	assert.NoError(t, err)
	assert.Equal(t, ct3.Property.Value(), prop.PropertyValue)
	if ct3.CreatedAt.UnixNano() < ct2.CreatedAt.UnixNano() {
		t.Errorf("ct3.CreatedAt: %s, ct2.CreatedAt: %s", ct3.CreatedAt.Format(time.RFC3339Nano), ct2.CreatedAt.Format(time.RFC3339Nano))
	}
	if ct3.LastSeen.UnixNano() < ct2.LastSeen.UnixNano() {
		t.Errorf("ct3.LastSeen: %s, ct2.LastSeen: %s", ct3.LastSeen.Format(time.RFC3339Nano), ct2.LastSeen.Format(time.RFC3339Nano))
	}

	tags, err := store.GetEntityTags(entity, now, "test")
	assert.NoError(t, err)

	var found bool
	for _, etag := range tags {
		if etag.Property.Value() == prop.PropertyValue {
			found = true
			break
		}
	}
	assert.Equal(t, found, true)

	err = store.DeleteEntityTag(ct3.ID)
	assert.NoError(t, err)

	_, err = store.FindEntityTagById(ct3.ID)
	assert.Error(t, err)
}

func TestEdgeTag(t *testing.T) {
	e1, err := store.CreateEntity(&domain.FQDN{Name: "owasp.org"})
	assert.NoError(t, err)

	e2, err := store.CreateEntity(&domain.FQDN{Name: "www.owasp.org"})
	assert.NoError(t, err)

	edge, err := store.Link(&types.Edge{
		Relation: &relation.BasicDNSRelation{
			Name:   "dns_record",
			Header: relation.RRHeader{RRType: 5},
		},
		FromEntity: e1,
		ToEntity:   e2,
	})
	assert.NoError(t, err)

	now := time.Now().Truncate(time.Second).UTC()
	prop := &property.SimpleProperty{
		PropertyName:  "test",
		PropertyValue: "foo",
	}

	ct, err := store.CreateEdgeTag(edge, prop)
	assert.NoError(t, err)
	assert.Equal(t, ct.Property.Name(), prop.PropertyName)
	assert.Equal(t, ct.Property.Value(), prop.PropertyValue)
	assert.Equal(t, oam.SimpleProperty, ct.Property.PropertyType())
	if now.After(ct.CreatedAt.UTC()) {
		t.Errorf("tag.CreatedAt: %s, expected to be after: %s", ct.CreatedAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	}
	if now.After(ct.LastSeen.UTC()) {
		t.Errorf("tag.LastSeen: %s, expected to be after: %s", ct.LastSeen.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	}

	tag, err := store.FindEdgeTagById(ct.ID)
	assert.NoError(t, err)
	assert.Equal(t, ct.CreatedAt, tag.CreatedAt)
	assert.Equal(t, ct.LastSeen, tag.LastSeen)
	assert.Equal(t, ct.Property.Name(), tag.Property.Name())
	assert.Equal(t, ct.Property.Value(), tag.Property.Value())

	time.Sleep(time.Second)
	ct2, err := store.CreateEdgeTag(edge, prop)
	assert.NoError(t, err)
	if ct2.LastSeen.UnixNano() < ct.LastSeen.UnixNano() {
		t.Errorf("ct2.LastSeen: %s, ct.LastSeen: %s", ct2.LastSeen.Format(time.RFC3339Nano), ct.LastSeen.Format(time.RFC3339Nano))
	}

	time.Sleep(time.Second)
	prop.PropertyValue = "bar"
	ct3, err := store.CreateEdgeTag(edge, prop)
	assert.NoError(t, err)
	assert.Equal(t, ct3.Property.Value(), prop.PropertyValue)
	if ct3.CreatedAt.UnixNano() < ct2.CreatedAt.UnixNano() {
		t.Errorf("ct3.CreatedAt: %s, ct2.CreatedAt: %s", ct3.CreatedAt.Format(time.RFC3339Nano), ct2.CreatedAt.Format(time.RFC3339Nano))
	}
	if ct3.LastSeen.UnixNano() < ct2.LastSeen.UnixNano() {
		t.Errorf("ct3.LastSeen: %s, ct2.LastSeen: %s", ct3.LastSeen.Format(time.RFC3339Nano), ct2.LastSeen.Format(time.RFC3339Nano))
	}

	tags, err := store.GetEdgeTags(edge, now, "test")
	assert.NoError(t, err)

	var found bool
	for _, etag := range tags {
		if etag.Property.Value() == prop.PropertyValue {
			found = true
			break
		}
	}
	assert.Equal(t, found, true)

	err = store.DeleteEdgeTag(ct3.ID)
	assert.NoError(t, err)

	_, err = store.FindEdgeTagById(ct3.ID)
	assert.Error(t, err)
}
