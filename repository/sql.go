// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DBType represents the type of the database.
type DBType string

const (
	// Postgres represents the PostgreSQL database type.
	Postgres DBType = "postgres"
	// SQLite represents the SQLite database type.
	SQLite DBType = "sqlite"
)

// sqlRepository is a repository implementation using GORM as the underlying ORM.
type sqlRepository struct {
	db     *gorm.DB
	dbType DBType
}

// New creates a new instance of the asset database repository.
func New(dbType DBType, dsn string) *sqlRepository {
	db, err := newDatabase(dbType, dsn)
	if err != nil {
		panic(err)
	}

	return &sqlRepository{
		db:     db,
		dbType: dbType,
	}
}

// newDatabase creates a new GORM database connection based on the provided database type and data source name (dsn).
func newDatabase(dbType DBType, dsn string) (*gorm.DB, error) {
	switch dbType {
	case Postgres:
		return postgresDatabase(dsn)
	case SQLite:
		return sqliteDatabase(dsn)
	default:
		panic("Unknown db type")
	}
}

// postgresDatabase creates a new PostgreSQL database connection using the provided data source name (dsn).
func postgresDatabase(dsn string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
}

// sqliteDatabase creates a new SQLite database connection using the provided data source name (dsn).
func sqliteDatabase(dsn string) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
}

// Close implements the Repository interface.
func (sql *sqlRepository) Close() error {
	if db, err := sql.db.DB(); err == nil {
		return db.Close()
	}
	return errors.New("failed to obtain access to the database handle")
}

// GetDBType returns the type of the database.
func (sql *sqlRepository) GetDBType() string {
	return string(sql.dbType)
}

// CreateAsset creates a new asset in the database.
// It takes an oam.Asset as input and persists it in the database.
// The asset is serialized to JSON and stored in the Content field of the Asset struct.
// Returns the created asset as a types.Asset or an error if the creation fails.
func (sql *sqlRepository) CreateAsset(assetData oam.Asset) (*types.Asset, error) {
	// ensure that duplicate relationships are not entered into the database
	if assets, err := sql.FindAssetByContent(assetData, time.Time{}); err == nil && len(assets) > 0 {
		for _, a := range assets {
			if assetData.AssetType() == a.Asset.AssetType() {
				err := sql.assetSeen(a)
				if err != nil {
					log.Println("[ERROR]: Failed to update last_seen: ", err)
					return nil, err
				}
				return sql.FindAssetById(a.ID, time.Time{})
			}
		}
	}

	jsonContent, err := assetData.JSON()
	if err != nil {
		return &types.Asset{}, err
	}

	asset := Asset{
		Type:    string(assetData.AssetType()),
		Content: jsonContent,
	}

	result := sql.db.Create(&asset)
	if result.Error != nil {
		return &types.Asset{}, result.Error
	}

	return &types.Asset{
		ID:        strconv.FormatUint(asset.ID, 10),
		CreatedAt: asset.CreatedAt,
		LastSeen:  asset.LastSeen,
		Asset:     assetData,
	}, nil
}

// updateLastSeen performs an update on the asset.
// this function delegates to the database so that the Timezone information is preserved.
func (sql *sqlRepository) assetSeen(asset *types.Asset) error {
	id, err := strconv.ParseInt(asset.ID, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to update last seen for ID %s could not parse id; err: %w", asset.ID, err)
	}

	result := sql.db.Exec("UPDATE assets SET last_seen = current_timestamp WHERE id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// DeleteAsset removes an asset in the database by its ID.
// It takes a string representing the asset ID and removes the corresponding asset from the database.
// Returns an error if the asset is not found.
func (sql *sqlRepository) DeleteAsset(id string) error {
	var ids []uint64

	if rels, err := sql.IncomingRelations(&types.Asset{ID: id}, time.Time{}); err == nil {
		for _, rel := range rels {
			if relId, err := strconv.ParseUint(rel.ID, 10, 64); err == nil {
				ids = append(ids, relId)
			}
		}
	}

	if rels, err := sql.OutgoingRelations(&types.Asset{ID: id}, time.Time{}); err == nil {
		for _, rel := range rels {
			if relId, err := strconv.ParseUint(rel.ID, 10, 64); err == nil {
				ids = append(ids, relId)
			}
		}
	}

	if err := sql.deleteRelations(ids); err != nil {
		return err
	}

	assetId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}

	asset := Asset{ID: assetId}
	result := sql.db.Delete(&asset)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

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
	return sql.db.Exec("DELETE FROM relations WHERE id IN ?", ids).Error
}

// FindAssetByContent finds assets in the database that match the provided asset data and last seen after the since parameter.
// It takes an oam.Asset as input and searches for assets with matching content in the database.
// If since.IsZero(), the parameter will be ignored.
// The asset data is serialized to JSON and compared against the Content field of the Asset struct.
// Returns a slice of matching assets as []*types.Asset or an error if the search fails.
func (sql *sqlRepository) FindAssetByContent(assetData oam.Asset, since time.Time) ([]*types.Asset, error) {
	jsonContent, err := assetData.JSON()
	if err != nil {
		return []*types.Asset{}, err
	}

	asset := Asset{
		Type:    string(assetData.AssetType()),
		Content: jsonContent,
	}
	if !since.IsZero() {
		asset.LastSeen = since
	}

	jsonQuery, err := asset.JSONQuery()
	if err != nil {
		return []*types.Asset{}, err
	}

	var assets []Asset
	var result *gorm.DB
	if since.IsZero() {
		result = sql.db.Where("type = ?", asset.Type).Find(&assets, jsonQuery)
	} else {
		result = sql.db.Where("type = ? AND last_seen > ?", asset.Type, since).Find(&assets, jsonQuery)
	}
	if result.Error != nil {
		return []*types.Asset{}, result.Error
	}

	var storedAssets []*types.Asset
	for _, asset := range assets {
		assetData, err := asset.Parse()
		if err != nil {
			return []*types.Asset{}, err
		}

		storedAssets = append(storedAssets, &types.Asset{
			ID:        strconv.FormatUint(asset.ID, 10),
			CreatedAt: asset.CreatedAt,
			LastSeen:  asset.LastSeen,
			Asset:     assetData,
		})
	}

	return storedAssets, nil
}

// FindAssetById finds an asset in the database by its ID and last seen after the since parameter.
// It takes a string representing the asset ID and retrieves the corresponding asset from the database.
// If since.IsZero(), the parameter will be ignored.
// Returns the found asset as a types.Asset or an error if the asset is not found.
func (sql *sqlRepository) FindAssetById(id string, since time.Time) (*types.Asset, error) {
	assetId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return &types.Asset{}, err
	}

	var result *gorm.DB
	asset := Asset{ID: assetId}
	if since.IsZero() {
		result = sql.db.First(&asset)
	} else {
		result = sql.db.Where("last_seen > ?", since).First(&asset)
	}
	if result.Error != nil {
		return &types.Asset{}, result.Error
	}

	assetData, err := asset.Parse()
	if err != nil {
		return &types.Asset{}, err
	}

	return &types.Asset{
		ID:        strconv.FormatUint(asset.ID, 10),
		CreatedAt: asset.CreatedAt,
		LastSeen:  asset.LastSeen,
		Asset:     assetData,
	}, nil
}

// FindAssetByType finds all assets in the database of the provided asset type and last seen after the since parameter.
// It takes an asset type and retrieves the corresponding assets from the database.
// If since.IsZero(), the parameter will be ignored.
// Returns a slice of matching assets as []*types.Asset or an error if the search fails.
func (sql *sqlRepository) FindAssetByType(atype oam.AssetType, since time.Time) ([]*types.Asset, error) {
	var assets []Asset
	var result *gorm.DB

	if since.IsZero() {
		result = sql.db.Where("type = ?", atype).Find(&assets)
	} else {
		result = sql.db.Where("type = ? AND last_seen > ?", atype, since).Find(&assets)
	}
	if result.Error != nil {
		return []*types.Asset{}, result.Error
	}

	var results []*types.Asset
	for _, a := range assets {
		if f, err := a.Parse(); err == nil {
			results = append(results, &types.Asset{
				ID:        strconv.FormatUint(a.ID, 10),
				CreatedAt: a.CreatedAt,
				LastSeen:  a.LastSeen,
				Asset:     f,
			})
		}
	}

	if len(results) == 0 {
		return []*types.Asset{}, errors.New("no assets of the specified type")
	}
	return results, nil
}

// Link creates a relation between two assets in the database.
// It takes the source asset, relation type, and destination asset as inputs.
// The relation is established by creating a new Relation struct in the database, linking the two assets.
// Returns the created relation as a types.Relation or an error if the link creation fails.
func (sql *sqlRepository) Link(source *types.Asset, relation string, destination *types.Asset) (*types.Relation, error) {
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

	fromAssetId, err := strconv.ParseUint(source.ID, 10, 64)
	if err != nil {
		return &types.Relation{}, err
	}

	toAssetId, err := strconv.ParseUint(destination.ID, 10, 64)
	if err != nil {
		return &types.Relation{}, err
	}

	r := Relation{
		Type:        relation,
		FromAssetID: fromAssetId,
		ToAssetID:   toAssetId,
	}

	result := sql.db.Create(&r)
	if result.Error != nil {
		return &types.Relation{}, result.Error
	}

	return toRelation(r), nil
}

// isDuplicateRelation checks if the relationship between source and dest already exists.
func (sql *sqlRepository) isDuplicateRelation(source *types.Asset, relation string, dest *types.Asset) (*types.Relation, bool) {
	var dup bool
	var rel *types.Relation

	if outs, err := sql.OutgoingRelations(source, time.Time{}, relation); err == nil {
		for _, out := range outs {
			if dest.ID == out.ToAsset.ID {
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
	result := sql.db.Exec("UPDATE relations SET last_seen = current_timestamp WHERE id = ?", id)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// IncomingRelations finds all relations pointing to the asset of the specified relation types and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no relationTypes are specified, all outgoing relations are returned.
func (sql *sqlRepository) IncomingRelations(asset *types.Asset, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	assetId, err := strconv.ParseInt(asset.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	relations := []Relation{}
	if len(relationTypes) > 0 {
		res := sql.db.Where("to_asset_id = ? AND type IN ?", assetId, relationTypes).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	} else {
		res := sql.db.Where("to_asset_id = ?", assetId).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	}

	return toRelations(relations), nil
}

// OutgoingRelations finds all relations from the asset of the specified relation types and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no relationTypes are specified, all outgoing relations are returned.
func (sql *sqlRepository) OutgoingRelations(asset *types.Asset, since time.Time, relationTypes ...string) ([]*types.Relation, error) {
	assetId, err := strconv.ParseInt(asset.ID, 10, 64)
	if err != nil {
		return nil, err
	}

	relations := []Relation{}
	if len(relationTypes) > 0 {
		res := sql.db.Where("from_asset_id = ? AND type IN ?", assetId, relationTypes).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	} else {
		res := sql.db.Where("from_asset_id = ?", assetId).Find(&relations)
		if res.Error != nil {
			return nil, res.Error
		}
	}

	return toRelations(relations), nil
}

func (sql *sqlRepository) relationById(id string) (*types.Relation, error) {
	rel := Relation{}

	result := sql.db.Where("id = ?", id).First(&rel)
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
		FromAsset: &types.Asset{
			ID: strconv.FormatUint(r.FromAssetID, 10),
			// Not joining to Asset to get Content
		},
		ToAsset: &types.Asset{
			ID: strconv.FormatUint(r.ToAssetID, 10),
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

// RayQuery creates a query and returns the slice of data returned.
func (sql *sqlRepository) RawQuery(sqlstr string, results interface{}) error {
	if result := sql.db.Raw(sqlstr).Scan(results); result.Error != nil {
		return result.Error
	}
	return nil
}

// AssetQuery creates a query and returns the slice of Assets found.
// The query will start with "SELECT assets.id, assets.create_at, assets.last_seen, assets.type, assets.content FROM "
// and then add the provided constraints. The query much include the assets table and remain named assets for parsing.
func (sql *sqlRepository) AssetQuery(constraints string) ([]*types.Asset, error) {
	var ga []Asset

	if constraints == "" {
		constraints = "assets"
	}

	result := sql.db.Raw("SELECT assets.id, assets.created_at, assets.last_seen, assets.type, assets.content FROM " + constraints).Scan(&ga)
	if result.Error != nil {
		return nil, result.Error
	}

	var assets []*types.Asset
	for _, a := range ga {
		if asset, err := sql.gormAssetToAsset(&a); err == nil {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func (sql *sqlRepository) gormAssetToAsset(ga *Asset) (*types.Asset, error) {
	asset, err := ga.Parse()
	if err != nil {
		return &types.Asset{}, err
	}

	return &types.Asset{
		ID:        strconv.FormatUint(ga.ID, 10),
		CreatedAt: ga.CreatedAt,
		LastSeen:  ga.LastSeen,
		Asset:     asset,
	}, nil
}

// RelationQuery creates a query and returns the slice of Relations found. The query will start with:
// "SELECT relations.id, relations.create_at, relations.last_seen, relations.type, relations.from_asset_id, relations.to_asset_id FROM "
// and then add the provided constraints. The query much include the relations table and remain named relations for parsing.
func (sql *sqlRepository) RelationQuery(constraints string) ([]*types.Relation, error) {
	var rs []*Relation

	if constraints == "" {
		constraints = "relations"
	}

	result := sql.db.Raw("SELECT relations.id, relations.created_at, relations.last_seen, relations.type, relations.from_asset_id, relations.to_asset_id FROM " + constraints).Scan(&rs)
	if result.Error != nil {
		return nil, result.Error
	}

	var relations []*types.Relation
	for _, r := range rs {
		if relation, err := sql.gormRelationToRelation(r); err == nil {
			relations = append(relations, relation)
		}
	}
	return relations, nil
}

func (sql *sqlRepository) gormRelationToRelation(gr *Relation) (*types.Relation, error) {
	fromasset, err := sql.FindAssetById(strconv.FormatUint(gr.FromAssetID, 10), time.Time{})
	if err != nil {
		return nil, err
	}
	toasset, err := sql.FindAssetById(strconv.FormatUint(gr.ToAssetID, 10), time.Time{})
	if err != nil {
		return nil, err
	}

	return &types.Relation{
		ID:        strconv.FormatUint(gr.ID, 10),
		CreatedAt: gr.CreatedAt,
		LastSeen:  gr.LastSeen,
		Type:      gr.Type,
		FromAsset: fromasset,
		ToAsset:   toasset,
	}, nil
}
