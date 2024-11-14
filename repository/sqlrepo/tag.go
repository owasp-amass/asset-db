// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlrepo

import (
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"gorm.io/gorm"
)

func (sql *sqlRepository) CreateEntityTag(entity *types.Entity, prop oam.Property) (*types.EntityTag, error) {
	jsonContent, err := prop.JSON()
	if err != nil {
		return nil, err
	}

	tag := EntityTag{
		Type:    string(prop.PropertyType()),
		Content: jsonContent,
	}

	// ensure that duplicate entity tags are not entered into the database
	if tags, err := sql.GetEntityTags(entity, time.Time{}, prop.Name()); err == nil && len(tags) > 0 {
		for _, t := range tags {
			if prop.PropertyType() == t.Property.PropertyType() && prop.Value() == t.Property.Value() {
				if id, err := strconv.ParseUint(t.ID, 10, 64); err == nil {
					tag.ID = id
					tag.CreatedAt = t.CreatedAt

					if sql.UpdateEntityTagLastSeen(t.ID) == nil {
						if f, err := sql.FindEntityTagById(t.ID); err == nil && f != nil {
							tag.LastSeen = f.LastSeen
							break
						}
					}
				}
			}
		}
	}

	result := sql.db.Save(&tag)
	if result.Error != nil {
		return nil, result.Error
	}

	return &types.EntityTag{
		ID:        strconv.FormatUint(tag.ID, 10),
		CreatedAt: tag.CreatedAt,
		LastSeen:  tag.LastSeen,
		Property:  prop,
	}, nil
}

// UpdateEntityTagLastSeen performs an update on the entity tag.
func (sql *sqlRepository) UpdateEntityTagLastSeen(id string) error {
	result := sql.db.Exec("UPDATE entity_tags SET last_seen = current_timestamp WHERE tag_id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// FindEntityTagById finds an entity tag in the database by the ID.
// It takes a string representing the entity tag ID and retrieves the corresponding tag from the database.
// Returns the discovered tag as a types.EntityTag or an error if the asset is not found.
func (sql *sqlRepository) FindEntityTagById(id string) (*types.EntityTag, error) {
	tagId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return nil, err
	}

	tag := EntityTag{ID: tagId}
	result := sql.db.First(&tag)
	if result.Error != nil {
		return nil, result.Error
	}

	data, err := tag.Parse()
	if err != nil {
		return nil, err
	}

	return &types.EntityTag{
		ID:        strconv.FormatUint(tag.ID, 10),
		CreatedAt: tag.CreatedAt,
		LastSeen:  tag.LastSeen,
		Property:  data,
	}, nil
}

// GetEntityTags finds all tag for the entity with the specified names and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no names are specified, all tags for the specified entity are returned.
func (sql *sqlRepository) GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	entityId, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	var tags []EntityTag
	var result *gorm.DB
	if since.IsZero() {
		result = sql.db.Where("entity_id = ?", entityId).Find(&tags)
	} else {
		result = sql.db.Where("entity_id = ? AND last_seen >= ?", entityId, since.UTC()).Find(&tags)
	}
	if err := result.Error; err != nil {
		return nil, err
	}

	var results []*types.EntityTag
	for _, tag := range tags {
		t := &tag

		if prop, err := t.Parse(); err == nil {
			found := true

			if len(names) > 0 {
				found = false
				n := prop.Name()

				for _, name := range names {
					if name == n {
						found = true
						break
					}
				}
			}

			if found {
				results = append(results, &types.EntityTag{
					ID:        strconv.Itoa(int(t.ID)),
					CreatedAt: t.CreatedAt,
					LastSeen:  t.LastSeen,
					Property:  prop,
				})
			}
		}
	}

	return results, nil
}

// DeleteEntityTag removes an entity tag in the database by its ID.
// It takes a string representing the entity tag ID and removes the corresponding tag from the database.
// Returns an error if the tag is not found.
func (sql *sqlRepository) DeleteEntityTag(id string) error {
	tagId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}

	tag := EntityTag{ID: tagId}
	result := sql.db.Delete(&tag)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (sql *sqlRepository) CreateEdgeTag(edge *types.Edge, prop oam.Property) (*types.EdgeTag, error) {
	jsonContent, err := prop.JSON()
	if err != nil {
		return nil, err
	}

	tag := EdgeTag{
		Type:    string(prop.PropertyType()),
		Content: jsonContent,
	}

	// ensure that duplicate edge tags are not entered into the database
	if tags, err := sql.GetEdgeTags(edge, time.Time{}, prop.Name()); err == nil && len(tags) > 0 {
		for _, t := range tags {
			if prop.PropertyType() == t.Property.PropertyType() && prop.Value() == t.Property.Value() {
				if id, err := strconv.ParseUint(t.ID, 10, 64); err == nil {
					tag.ID = id
					tag.CreatedAt = t.CreatedAt

					if sql.UpdateEdgeTagLastSeen(t.ID) == nil {
						if f, err := sql.FindEdgeTagById(t.ID); err == nil && f != nil {
							tag.LastSeen = f.LastSeen
							break
						}
					}
				}
			}
		}
	}

	result := sql.db.Save(&tag)
	if result.Error != nil {
		return nil, result.Error
	}

	return &types.EdgeTag{
		ID:        strconv.FormatUint(tag.ID, 10),
		CreatedAt: tag.CreatedAt,
		LastSeen:  tag.LastSeen,
		Property:  prop,
	}, nil
}

// UpdateEdgeTagLastSeen performs an update on the edge tag.
func (sql *sqlRepository) UpdateEdgeTagLastSeen(id string) error {
	result := sql.db.Exec("UPDATE edge_tags SET last_seen = current_timestamp WHERE tag_id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// FindEdgeTagById finds an edge tag in the database by the ID.
// It takes a string representing the edge tag ID and retrieves the corresponding tag from the database.
// Returns the discovered tag as a types.EdgeTag or an error if the asset is not found.
func (sql *sqlRepository) FindEdgeTagById(id string) (*types.EdgeTag, error) {
	tagId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return nil, err
	}

	tag := EdgeTag{ID: tagId}
	result := sql.db.First(&tag)
	if result.Error != nil {
		return nil, result.Error
	}

	data, err := tag.Parse()
	if err != nil {
		return nil, err
	}

	return &types.EdgeTag{
		ID:        strconv.FormatUint(tag.ID, 10),
		CreatedAt: tag.CreatedAt,
		LastSeen:  tag.LastSeen,
		Property:  data,
	}, nil
}

func (sql *sqlRepository) GetEdgeTags(edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {
	edgeId, err := strconv.ParseInt(edge.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	var tags []EdgeTag
	var result *gorm.DB
	if since.IsZero() {
		result = sql.db.Where("edge_id = ?", edgeId).Find(&tags)
	} else {
		result = sql.db.Where("edge_id = ? AND last_seen >= ?", edgeId, since.UTC()).Find(&tags)
	}
	if err := result.Error; err != nil {
		return nil, err
	}

	var results []*types.EdgeTag
	for _, tag := range tags {
		t := &tag

		if prop, err := t.Parse(); err == nil {
			found := true

			if len(names) > 0 {
				found = false
				n := prop.Name()

				for _, name := range names {
					if name == n {
						found = true
						break
					}
				}
			}

			if found {
				results = append(results, &types.EdgeTag{
					ID:        strconv.Itoa(int(t.ID)),
					CreatedAt: t.CreatedAt,
					LastSeen:  t.LastSeen,
					Property:  prop,
				})
			}
		}
	}

	return results, nil
}

// DeleteEdgeTag removes an edge tag in the database by its ID.
// It takes a string representing the edge tag ID and removes the corresponding tag from the database.
// Returns an error if the tag is not found.
func (sql *sqlRepository) DeleteEdgeTag(id string) error {
	tagId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}

	tag := EdgeTag{ID: tagId}
	result := sql.db.Delete(&tag)
	if result.Error != nil {
		return result.Error
	}
	return nil
}
