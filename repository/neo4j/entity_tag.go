// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// CreateEntityTag creates a new entity tag in the database.
// It takes an EntityTag as input and persists it in the database.
// The property is serialized to JSON and stored in the Content field of the EntityTag struct.
// Returns the created entity tag as a types.EntityTag or an error if the creation fails.
func (neo *neoRepository) CreateEntityTag(entity *types.Entity, input *types.EntityTag) (*types.EntityTag, error) {
	var tag *types.EntityTag

	if input == nil {
		return nil, errors.New("the input entity tag is nil")
	}
	// ensure that duplicate entities are not entered into the database
	if tags, err := neo.FindEntityTagsByContent(input.Property, time.Time{}); err == nil && len(tags) > 0 {
		t := tags[0]

		if input.Property.PropertyType() != t.Property.PropertyType() {
			return nil, errors.New("the property type does not match the existing tag")
		}

		qnode, err := queryNodeByPropertyKeyValue("p", "EntityTag", t.Property)
		if err != nil {
			return nil, err
		}

		t.Entity = entity
		t.LastSeen = time.Now()
		props, err := entityTagPropsMap(t)
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := neo4jdb.ExecuteQuery(ctx, neo.db,
			"MATCH "+qnode+" SET p = $props RETURN p",
			map[string]interface{}{"props": props},
			neo4jdb.EagerResultTransformer,
			neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
		)
		if err != nil {
			return nil, err
		}
		if len(result.Records) == 0 {
			return nil, errors.New("no records returned from the query")
		}

		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "p")
		if err != nil {
			return nil, err
		}
		if isnil {
			return nil, errors.New("the record value for the node is nil")
		}

		if extracted, err := nodeToEntityTag(node); err == nil && extracted != nil {
			tag = extracted
		}
	} else {
		if input.ID == "" {
			input.ID = neo.uniqueEntityTagID()
		}
		if input.CreatedAt.IsZero() {
			input.CreatedAt = time.Now()
		}
		if input.LastSeen.IsZero() {
			input.LastSeen = time.Now()
		}

		input.Entity = entity
		props, err := entityTagPropsMap(input)
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		query := fmt.Sprintf("CREATE (p:EntityTag:%s $props) RETURN p", input.Property.PropertyType())
		result, err := neo4jdb.ExecuteQuery(ctx, neo.db, query,
			map[string]interface{}{"props": props},
			neo4jdb.EagerResultTransformer,
			neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
		)
		if err != nil {
			return nil, err
		}
		if len(result.Records) == 0 {
			return nil, errors.New("no records returned from the query")
		}

		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "p")
		if err != nil {
			return nil, err
		}
		if isnil {
			return nil, errors.New("the record value for the node is nil")
		}

		if t, err := nodeToEntityTag(node); err == nil && t != nil {
			tag = t
		}
	}

	if tag == nil {
		return nil, errors.New("failed to create the entity tag")
	}
	return tag, nil
}

// CreateEntityProperty creates a new entity tag in the database.
// It takes an oam.Property as input and persists it in the database.
// The property is serialized to JSON and stored in the Content field of the EntityTag struct.
// Returns the created entity tag as a types.EntityTag or an error if the creation fails.
func (neo *neoRepository) CreateEntityProperty(entity *types.Entity, prop oam.Property) (*types.EntityTag, error) {
	return neo.CreateEntityTag(entity, &types.EntityTag{Property: prop})
}

func (neo *neoRepository) uniqueEntityTagID() string {
	for {
		id := uuid.New().String()
		if _, err := neo.FindEntityTagById(id); err != nil {
			return id
		}
	}
}

// FindEntityTagById finds an entity tag in the database by the ID.
// It takes a string representing the entity tag ID and retrieves the corresponding tag from the database.
// Returns the discovered tag as a types.EntityTag or an error if the asset is not found.
func (neo *neoRepository) FindEntityTagById(id string) (*types.EntityTag, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db,
		"MATCH (p:EntityTag {tag_id: $tid}) RETURN p",
		map[string]interface{}{"tid": id},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, fmt.Errorf("the entity tag with ID %s was not found", id)
	}

	node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "p")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the node is nil")
	}
	return nodeToEntityTag(node)
}

// FindEntityTagsByContent finds entity tags in the database that match the provided property data and updated_at after the since parameter.
// It takes an oam.Property as input and searches for entity tags with matching content in the database.
// If since.IsZero(), the parameter will be ignored.
// The property data is serialized to JSON and compared against the Content field of the EntityTag struct.
// Returns a slice of matching entity tags as []*types.EntityTag or an error if the search fails.
func (neo *neoRepository) FindEntityTagsByContent(prop oam.Property, since time.Time) ([]*types.EntityTag, error) {
	qnode, err := queryNodeByPropertyKeyValue("p", "EntityTag", prop)
	if err != nil {
		return nil, err
	}

	query := "MATCH " + qnode + " RETURN p"
	if !since.IsZero() {
		query = fmt.Sprintf("MATCH %s WHERE p.updated_at >= localDateTime('%s') RETURN p", qnode, timeToNeo4jTime(since))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db, query, nil,
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, errors.New("no entity tags found")
	}

	node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "p")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the node is nil")
	}

	tag, err := nodeToEntityTag(node)
	if err != nil {
		return nil, err
	}
	return []*types.EntityTag{tag}, nil
}

// GetEntityTags finds all tags for the entity with the specified names and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no names are specified, all tags for the specified entity are returned.
func (neo *neoRepository) GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	query := fmt.Sprintf("MATCH (p:EntityTag {entity_id: '%s'}) RETURN p", entity.ID)
	if !since.IsZero() {
		query = fmt.Sprintf("MATCH (p:EntityTag {entity_id: '%s'}) WHERE p.updated_at >= localDateTime('%s') RETURN p", entity.ID, timeToNeo4jTime(since))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db, query, nil,
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, errors.New("no entity tags found")
	}

	var results []*types.EntityTag
	for _, record := range result.Records {
		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](record, "p")
		if err != nil {
			continue
		}
		if isnil {
			continue
		}

		tag, err := nodeToEntityTag(node)
		if err != nil {
			continue
		}

		if len(names) > 0 {
			var found bool
			n := tag.Property.Name()

			for _, name := range names {
				if name == n {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		results = append(results, tag)
	}

	if len(results) == 0 {
		return nil, errors.New("zero tags found")
	}
	return results, nil
}

// DeleteEntityTag removes an entity tag in the database by its ID.
// It takes a string representing the entity tag ID and removes the corresponding tag from the database.
// Returns an error if the tag is not found.
func (neo *neoRepository) DeleteEntityTag(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := neo4jdb.ExecuteQuery(ctx, neo.db,
		"MATCH (n:EntityTag {tag_id: $tid}) DETACH DELETE n",
		map[string]interface{}{
			"tid": id,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)

	return err
}
