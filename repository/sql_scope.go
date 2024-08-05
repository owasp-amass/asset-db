// Copyright © by Jeff Foley 2022-2024. All rights reserved.
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

// FindAssetByScope finds assets in the database by applying all the scope constraints provided and last seen after the since parameter.
// It takes a slice representing the set of constraints to serve as the scope and retrieves the corresponding assets from the database.
// If since.IsZero(), the parameter will be ignored.
// Returns a slice of matching assets as []*types.Asset or an error if the search fails.
func (sql *sqlRepository) FindAssetByScope(constraints []oam.Asset, since time.Time) ([]*types.Asset, error) {
	var findings []*types.Asset

	for _, constraint := range constraints {
		if assets, err := sql.constraintEdgeCases(constraint, since); err == nil {
			for _, a := range assets {
				if f, err := a.Parse(); err == nil {
					findings = append(findings, &types.Asset{
						ID:        strconv.FormatUint(a.ID, 10),
						CreatedAt: a.CreatedAt,
						LastSeen:  a.LastSeen,
						Asset:     f,
					})
				}
			}
		}

		if assets, err := sql.inAndOut(constraint, since); err == nil {
			findings = append(findings, assets...)
		}
	}

	if len(findings) == 0 {
		return []*types.Asset{}, errors.New("no assets in scope")
	}
	return findings, nil
}

func (sql *sqlRepository) inAndOut(constraint oam.Asset, since time.Time) ([]*types.Asset, error) {
	constraints, err := sql.FindAssetByContent(constraint, time.Time{})
	if err != nil || len(constraints) == 0 {
		return constraints, err
	}

	ids := stringset.New()
	for _, constraint := range constraints {
		if rels, err := sql.IncomingRelations(constraint, since); err == nil {
			for _, rel := range rels {
				ids.Insert(rel.FromAsset.ID)
			}
		}

		if rels, err := sql.OutgoingRelations(constraint, since); err == nil {
			for _, rel := range rels {
				ids.Insert(rel.ToAsset.ID)
			}
		}
	}

	var assets []*types.Asset
	for _, id := range ids.Slice() {
		if a, err := sql.FindAssetById(id, since); err == nil {
			assets = append(assets, a)
		}
	}

	if len(assets) == 0 {
		return []*types.Asset{}, errors.New("no assets in scope")
	}
	return assets, nil
}

func (sql *sqlRepository) constraintEdgeCases(constraint oam.Asset, since time.Time) ([]Asset, error) {
	switch v := constraint.(type) {
	case *domain.FQDN:
		return sql.fqdnToEmails(v, since)
	}
	return nil, errors.New("no results found")
}

func (sql *sqlRepository) fqdnToEmails(fqdn *domain.FQDN, since time.Time) ([]Asset, error) {
	var assets []Asset
	var result *gorm.DB

	if since.IsZero() {
		result = sql.db.Where("type = ? AND content->>'address' LIKE ?", oam.EmailAddress, "%"+fqdn.Name).Find(&assets)
	} else {
		result = sql.db.Where("type = ? AND content->>'address' LIKE ? AND last_seen > ?", oam.EmailAddress, "%"+fqdn.Name, since).Find(&assets)
	}

	return assets, result.Error
}
