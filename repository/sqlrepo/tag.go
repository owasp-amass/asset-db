// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlrepo

import (
	"errors"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"gorm.io/gorm"
)

// CreateEntityTag creates a new entity tag in the database.
// It takes an EntityTag as input and persists it in the database.
// The property is serialized to JSON and stored in the Content field of the EntityTag struct.
// Returns the created entity tag as a types.EntityTag or an error if the creation fails.
func (sql *sqlRepository) CreateEntityTag(entity *types.Entity, input *types.EntityTag) (*types.EntityTag, error) {
	entityid, err := strconv.ParseUint(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	jsonContent, err := input.Property.JSON()
	if err != nil {
		return nil, err
	}

	tag := EntityTag{
		Type:     string(input.Property.PropertyType()),
		Content:  jsonContent,
		EntityID: entityid,
	}

	// ensure that duplicate entity tags are not entered into the database
	if tags, err := sql.GetEntityTags(entity, time.Time{}, input.Property.Name()); err == nil && len(tags) > 0 {
		for _, t := range tags {
			if input.Property.PropertyType() == t.Property.PropertyType() && input.Property.Value() == t.Property.Value() {
				if id, err := strconv.ParseUint(t.ID, 10, 64); err == nil {
					tag.ID = id
					tag.CreatedAt = t.CreatedAt
					tag.UpdatedAt = time.Now().UTC()
					break
				}
			}
		}
	} else {
		if input.CreatedAt.IsZero() {
			tag.CreatedAt = time.Now().UTC()
		} else {
			tag.CreatedAt = input.CreatedAt.UTC()
		}

		if input.LastSeen.IsZero() {
			tag.UpdatedAt = time.Now().UTC()
		} else {
			tag.UpdatedAt = input.LastSeen.UTC()
		}
	}

	result := sql.db.Save(&tag)
	if err := result.Error; err != nil {
		return nil, err
	}

	return &types.EntityTag{
		ID:        strconv.FormatUint(tag.ID, 10),
		CreatedAt: tag.CreatedAt.In(time.UTC).Local(),
		LastSeen:  tag.UpdatedAt.In(time.UTC).Local(),
		Property:  input.Property,
		Entity:    entity,
	}, nil
}

// CreateEntityProperty creates a new entity tag in the database.
// It takes an oam.Property as input and persists it in the database.
// The property is serialized to JSON and stored in the Content field of the EntityTag struct.
// Returns the created entity tag as a types.EntityTag or an error if the creation fails.
func (sql *sqlRepository) CreateEntityProperty(entity *types.Entity, prop oam.Property) (*types.EntityTag, error) {
	return sql.CreateEntityTag(entity, &types.EntityTag{Property: prop})
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
	if err := result.Error; err != nil {
		return nil, err
	}

	data, err := tag.Parse()
	if err != nil {
		return nil, err
	}

	return &types.EntityTag{
		ID:        strconv.FormatUint(tag.ID, 10),
		CreatedAt: tag.CreatedAt.In(time.UTC).Local(),
		LastSeen:  tag.UpdatedAt.In(time.UTC).Local(),
		Property:  data,
		Entity:    &types.Entity{ID: strconv.FormatUint(tag.EntityID, 10)},
	}, nil
}

// FindEntityTagsByContent finds entity tags in the database that match the provided property data and updated_at after the since parameter.
// It takes an oam.Property as input and searches for entity tags with matching content in the database.
// If since.IsZero(), the parameter will be ignored.
// The property data is serialized to JSON and compared against the Content field of the EntityTag struct.
// Returns a slice of matching entity tags as []*types.EntityTag or an error if the search fails.
func (sql *sqlRepository) FindEntityTagsByContent(prop oam.Property, since time.Time) ([]*types.EntityTag, error) {
	jsonContent, err := prop.JSON()
	if err != nil {
		return nil, err
	}

	tag := EntityTag{
		Type:    string(prop.PropertyType()),
		Content: jsonContent,
	}

	nameQuery, err := tag.NameJSONQuery()
	if err != nil {
		return nil, err
	}

	valueQuery, err := tag.ValueJSONQuery()
	if err != nil {
		return nil, err
	}

	tx := sql.db.Where("ttype = ?", tag.Type)
	if !since.IsZero() {
		tx = tx.Where("updated_at >= ?", since.UTC())
	}

	var tags []EntityTag
	tx = tx.Where(nameQuery).Where(valueQuery).Find(&tags)
	if err := tx.Error; err != nil {
		return nil, err
	}

	var results []*types.EntityTag
	for _, t := range tags {
		if propData, err := t.Parse(); err == nil {
			results = append(results, &types.EntityTag{
				ID:        strconv.FormatUint(t.ID, 10),
				CreatedAt: t.CreatedAt.In(time.UTC).Local(),
				LastSeen:  t.UpdatedAt.In(time.UTC).Local(),
				Property:  propData,
				Entity:    &types.Entity{ID: strconv.FormatUint(t.EntityID, 10)},
			})
		}
	}

	if len(results) == 0 {
		return nil, errors.New("zero entity tags found")
	}
	return results, nil
}

// GetEntityTags finds all tags for the entity with the specified names and last seen after the since parameter.
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
		result = sql.db.Where("entity_id = ? AND updated_at >= ?", entityId, since.UTC()).Find(&tags)
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
					CreatedAt: t.CreatedAt.In(time.UTC).Local(),
					LastSeen:  t.UpdatedAt.In(time.UTC).Local(),
					Property:  prop,
					Entity:    entity,
				})
			}
		}
	}

	if len(results) == 0 {
		return nil, errors.New("zero tags found")
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
	if err := result.Error; err != nil {
		return err
	}
	return nil
}

// CreateEdgeTag creates a new edge tag in the database.
// It takes an EdgeTag as input and persists it in the database.
// The property is serialized to JSON and stored in the Content field of the EdgeTag struct.
// Returns the created edge tag as a types.EdgeTag or an error if the creation fails.
func (sql *sqlRepository) CreateEdgeTag(edge *types.Edge, input *types.EdgeTag) (*types.EdgeTag, error) {
	edgeid, err := strconv.ParseUint(edge.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	jsonContent, err := input.Property.JSON()
	if err != nil {
		return nil, err
	}

	tag := EdgeTag{
		Type:    string(input.Property.PropertyType()),
		Content: jsonContent,
		EdgeID:  edgeid,
	}

	// ensure that duplicate edge tags are not entered into the database
	if tags, err := sql.GetEdgeTags(edge, time.Time{}, input.Property.Name()); err == nil && len(tags) > 0 {
		for _, t := range tags {
			if input.Property.PropertyType() == t.Property.PropertyType() && input.Property.Value() == t.Property.Value() {
				if id, err := strconv.ParseUint(t.ID, 10, 64); err == nil {
					tag.ID = id
					tag.CreatedAt = t.CreatedAt
					tag.UpdatedAt = time.Now().UTC()
					break
				}
			}
		}
	} else {
		if input.CreatedAt.IsZero() {
			tag.CreatedAt = time.Now().UTC()
		} else {
			tag.CreatedAt = input.CreatedAt.UTC()
		}

		if input.LastSeen.IsZero() {
			tag.UpdatedAt = time.Now().UTC()
		} else {
			tag.UpdatedAt = input.LastSeen.UTC()
		}
	}

	result := sql.db.Save(&tag)
	if err := result.Error; err != nil {
		return nil, err
	}

	return &types.EdgeTag{
		ID:        strconv.FormatUint(tag.ID, 10),
		CreatedAt: tag.CreatedAt.In(time.UTC).Local(),
		LastSeen:  tag.UpdatedAt.In(time.UTC).Local(),
		Property:  input.Property,
		Edge:      edge,
	}, nil
}

// CreateEdgeProperty creates a new edge tag in the database.
// It takes an oam.Property as input and persists it in the database.
// The property is serialized to JSON and stored in the Content field of the EdgeTag struct.
// Returns the created edge tag as a types.EdgeTag or an error if the creation fails.
func (sql *sqlRepository) CreateEdgeProperty(edge *types.Edge, prop oam.Property) (*types.EdgeTag, error) {
	return sql.CreateEdgeTag(edge, &types.EdgeTag{Property: prop})
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
	if err := result.Error; err != nil {
		return nil, err
	}

	data, err := tag.Parse()
	if err != nil {
		return nil, err
	}

	edge, err := sql.FindEdgeById(strconv.FormatUint(tag.EdgeID, 10))
	if err != nil {
		return nil, err
	}

	return &types.EdgeTag{
		ID:        strconv.FormatUint(tag.ID, 10),
		CreatedAt: tag.CreatedAt.In(time.UTC).Local(),
		LastSeen:  tag.UpdatedAt.In(time.UTC).Local(),
		Property:  data,
		Edge:      edge,
	}, nil
}

// FindEdgeTagsByContent finds edge tags in the database that match the provided property data and updated_at after the since parameter.
// It takes an oam.Property as input and searches for edge tags with matching content in the database.
// If since.IsZero(), the parameter will be ignored.
// The property data is serialized to JSON and compared against the Content field of the EdgeTag struct.
// Returns a slice of matching edge tags as []*types.EdgeTag or an error if the search fails.
func (sql *sqlRepository) FindEdgeTagsByContent(prop oam.Property, since time.Time) ([]*types.EdgeTag, error) {
	jsonContent, err := prop.JSON()
	if err != nil {
		return nil, err
	}

	tag := EdgeTag{
		Type:    string(prop.PropertyType()),
		Content: jsonContent,
	}

	nameQuery, err := tag.NameJSONQuery()
	if err != nil {
		return nil, err
	}

	valueQuery, err := tag.ValueJSONQuery()
	if err != nil {
		return nil, err
	}

	tx := sql.db.Where("ttype = ?", tag.Type)
	if !since.IsZero() {
		tx = tx.Where("updated_at >= ?", since.UTC())
	}

	var tags []EdgeTag
	tx = tx.Where(nameQuery).Where(valueQuery).Find(&tags)
	if err := tx.Error; err != nil {
		return nil, err
	}

	var results []*types.EdgeTag
	for _, t := range tags {
		if propData, err := t.Parse(); err == nil {
			results = append(results, &types.EdgeTag{
				ID:        strconv.FormatUint(t.ID, 10),
				CreatedAt: t.CreatedAt.In(time.UTC).Local(),
				LastSeen:  t.UpdatedAt.In(time.UTC).Local(),
				Property:  propData,
				Edge:      &types.Edge{ID: strconv.FormatUint(t.EdgeID, 10)},
			})
		}
	}

	if len(results) == 0 {
		return nil, errors.New("zero edge tags found")
	}
	return results, nil
}

// GetEdgeTags finds all tags for the edge with the specified names and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no names are specified, all tags for the specified edge are returned.
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
		result = sql.db.Where("edge_id = ? AND updated_at >= ?", edgeId, since.UTC()).Find(&tags)
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
					CreatedAt: t.CreatedAt.In(time.UTC).Local(),
					LastSeen:  t.UpdatedAt.In(time.UTC).Local(),
					Property:  prop,
					Edge:      edge,
				})
			}
		}
	}

	if len(results) == 0 {
		return nil, errors.New("zero tags found")
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
	if err := result.Error; err != nil {
		return err
	}
	return nil
}
