// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"errors"
	"strconv"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"gorm.io/gorm"
)

// FindEntitiesByScope finds entities in the database by applying all the scope constraints provided and last seen after the since parameter.
// It takes a slice representing the set of constraints to serve as the scope and retrieves the corresponding entities from the database.
// If since.IsZero(), the parameter will be ignored.
// Returns a slice of matching entities as []*types.Entity or an error if the search fails.
func (sql *sqlRepository) FindEntitiesByScope(constraints []oam.Asset, since time.Time) ([]*types.Entity, error) {
	var findings []*types.Entity

	for _, constraint := range constraints {
		if entities, err := sql.constraintEdgeCases(constraint, since); err == nil {
			for _, e := range entities {
				if f, err := e.Parse(); err == nil {
					findings = append(findings, &types.Entity{
						ID:        strconv.FormatUint(e.ID, 10),
						CreatedAt: e.CreatedAt,
						LastSeen:  e.LastSeen,
						Asset:     f,
					})
				}
			}
		}

		if entities, err := sql.inAndOut(constraint, since); err == nil {
			findings = append(findings, entities...)
		}
	}

	if len(findings) == 0 {
		return []*types.Entity{}, errors.New("no entities in scope")
	}
	return findings, nil
}

func (sql *sqlRepository) inAndOut(constraint oam.Asset, since time.Time) ([]*types.Entity, error) {
	constraints, err := sql.FindEntityByContent(constraint, time.Time{})
	if err != nil || len(constraints) == 0 {
		return constraints, err
	}

	ids := stringset.New()
	for _, constraint := range constraints {
		if rels, err := sql.IncomingRelations(constraint, since); err == nil {
			for _, rel := range rels {
				ids.Insert(rel.FromEntity.ID)
			}
		}

		if rels, err := sql.OutgoingRelations(constraint, since); err == nil {
			for _, rel := range rels {
				ids.Insert(rel.ToEntity.ID)
			}
		}
	}

	var entities []*types.Entity
	for _, id := range ids.Slice() {
		if e, err := sql.FindEntityById(id, since); err == nil {
			entities = append(entities, e)
		}
	}

	if len(entities) == 0 {
		return []*types.Entity{}, errors.New("no entities in scope")
	}
	return entities, nil
}

func (sql *sqlRepository) constraintEdgeCases(constraint oam.Asset, since time.Time) ([]Entity, error) {
	switch v := constraint.(type) {
	case *domain.FQDN:
		return sql.fqdnToEmails(v, since)
	}
	return nil, errors.New("no results found")
}

func (sql *sqlRepository) fqdnToEmails(fqdn *domain.FQDN, since time.Time) ([]Entity, error) {
	var entities []Entity
	var result *gorm.DB

	if since.IsZero() {
		result = sql.db.Where("etype = ? AND content->>'address' LIKE ?", oam.EmailAddress, "%"+fqdn.Name).Find(&entities)
	} else {
		result = sql.db.Where("etype = ? AND content->>'address' LIKE ? AND last_seen > ?", oam.EmailAddress, "%"+fqdn.Name, since).Find(&entities)
	}

	return entities, result.Error
}
