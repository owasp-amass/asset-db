// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// DeleteRelation removes a relation in the database by its ID.
// It takes a string representing the relation ID and removes the corresponding relation from the database.
// Returns an error if the relation is not found.
func (sql *sqlRepository) DeleteRelation(id string) error {
	relId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}
	return sql.deleteRelations([]uint64{relId})
}

// deleteRelations removes all rows in the Relations table with primary keys in the provided slice.
func (sql *sqlRepository) deleteRelations(ids []uint64) error {
	return sql.db.Exec("DELETE FROM relations WHERE relation_id IN ?", ids).Error
}

// Link creates a relation between two entities in the database.
// It takes the source entity, relation type, and destination entity as inputs.
// The relation is established by creating a new Relation struct in the database, linking the two entities.
// Returns the created relation as a types.Relation or an error if the link creation fails.
func (sql *sqlRepository) Link(source *types.Entity, relation string, destination *types.Entity) (*types.Relation, error) {
	// check that this link will create a valid relationship within the taxonomy
	srctype := source.Asset.AssetType()
	destype := destination.Asset.AssetType()
	if !oam.ValidRelationship(srctype, relation, destype) {
		return &types.Relation{}, fmt.Errorf("%s -%s-> %s is not valid in the taxonomy", srctype, relation, destype)
	}

	// ensure that duplicate relationships are not entered into the database
	if rel, found := sql.isDuplicateRelation(source, relation, destination); found {
		return rel, nil
	}

	fromEntityId, err := strconv.ParseUint(source.ID, 10, 64)
	if err != nil {
		return &types.Relation{}, err
	}

	toEntityId, err := strconv.ParseUint(destination.ID, 10, 64)
	if err != nil {
		return &types.Relation{}, err
	}

	r := Relation{
		Type:         relation,
		FromEntityID: fromEntityId,
		ToEntityID:   toEntityId,
	}

	result := sql.db.Create(&r)
	if result.Error != nil {
		return &types.Relation{}, result.Error
	}

	return toRelation(r), nil
}

// isDuplicateRelation checks if the relationship between source and dest already exists.
func (sql *sqlRepository) isDuplicateRelation(source *types.Entity, relation string, dest *types.Entity) (*types.Relation, bool) {
	var dup bool
	var rel *types.Relation

	if outs, err := sql.OutgoingRelations(source, time.Time{}, relation); err == nil {
		for _, out := range outs {
			if dest.ID == out.ToEntity.ID {
				_ = sql.relationSeen(out)
				rel, err = sql.relationById(out.ID)
				if err != nil {
					log.Println("[ERROR] failed when re-retrieving relation", err)
					return nil, false
				}
				dup = true
				break
			}
		}
	}
	return rel, dup
}

// updateRelationLastSeen updates the last seen timestamp for the specified relation.
func (sql *sqlRepository) relationSeen(rel *types.Relation) error {
	id, err := strconv.ParseInt(rel.ID, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to update last seen for ID %s could not parse id; err: %w", rel.ID, err)
	}

	result := sql.db.Exec("UPDATE relations SET last_seen = current_timestamp WHERE relation_id = ?", id)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// IncomingRelations finds all relations pointing to the entity of the specified relation types and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no relationTypes are specified, all outgoing relations are returned.
func (sql *sqlRepository) IncomingRelations(entity *types.Entity, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	entityId, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	relations := []Relation{}
	if len(relationTypes) > 0 {
		res := sql.db.Where("to_entity_id = ? AND type IN ?", entityId, relationTypes).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	} else {
		res := sql.db.Where("to_entity_id = ?", entityId).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	}

	return toRelations(relations), nil
}

// OutgoingRelations finds all relations from the entity of the specified relation types and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no relationTypes are specified, all outgoing relations are returned.
func (sql *sqlRepository) OutgoingRelations(entity *types.Entity, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	entityId, err := strconv.ParseInt(entity.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	relations := []Relation{}
	if len(relationTypes) > 0 {
		res := sql.db.Where("from_entity_id = ? AND type IN ?", entityId, relationTypes).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	} else {
		res := sql.db.Where("from_entity_id = ?", entityId).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	}

	return toRelations(relations), nil
}

func (sql *sqlRepository) relationById(id string) (*types.Relation, error) {
	rel := Relation{}

	result := sql.db.Where("relation_id = ?", id).First(&rel)
	if result.Error != nil {
		return nil, result.Error
	}

	return toRelation(rel), nil
}

// toRelation converts a database Relation to a types.Relation.
func toRelation(r Relation) *types.Relation {
	rel := &types.Relation{
		ID:       strconv.FormatUint(r.ID, 10),
		Type:     r.Type,
		LastSeen: r.LastSeen,
		FromEntity: &types.Entity{
			ID: strconv.FormatUint(r.FromEntityID, 10),
			// Not joining to Asset to get Content
		},
		ToEntity: &types.Entity{
			ID: strconv.FormatUint(r.ToEntityID, 10),
			// Not joining to Asset to get Content
		},
	}
	return rel
}

// toRelations converts a slice database Relations to a slice of types.Relation structs.
func toRelations(relations []Relation) []*types.Relation {
	var res []*types.Relation

	for _, r := range relations {
		res = append(res, toRelation(r))
	}

	return res
}
