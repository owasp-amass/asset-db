// Copyright © by Jeff Foley 2017-2024. All rights reserved.
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

// CreateEdgeTag creates a new edge tag in the database.
// It takes an EdgeTag as input and persists it in the database.
// The property is serialized to JSON and stored in the Content field of the EdgeTag struct.
// Returns the created edge tag as a types.EdgeTag or an error if the creation fails.
func (neo *neoRepository) CreateEdgeTag(edge *types.Edge, input *types.EdgeTag) (*types.EdgeTag, error) {
	var tag *types.EdgeTag

	if input == nil {
		return nil, errors.New("the input edge tag is nil")
	}
	// ensure that duplicate entities are not entered into the database
	if tags, err := neo.FindEdgeTagsByContent(input.Property, time.Time{}); err == nil && len(tags) == 1 {
		t := tags[0]

		if input.Property.PropertyType() != t.Property.PropertyType() {
			return nil, errors.New("the property type does not match the existing tag")
		}

		qnode, err := queryNodeByPropertyKeyValue("p", "EdgeTag", t.Property)
		if err != nil {
			return nil, err
		}

		t.LastSeen = time.Now()
		props, err := edgeTagPropsMap(t)
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

		if extracted, err := nodeToEdgeTag(node); err == nil && extracted != nil {
			tag = extracted
		}
	} else {
		if input.ID == "" {
			input.ID = neo.uniqueEdgeTagID()
		}
		if input.CreatedAt.IsZero() {
			input.CreatedAt = time.Now()
		}
		if input.LastSeen.IsZero() {
			input.LastSeen = time.Now()
		}

		props, err := edgeTagPropsMap(input)
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		query := fmt.Sprintf("CREATE (p:EdgeTag:%s $props) RETURN p", input.Property.PropertyType())
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

		if t, err := nodeToEdgeTag(node); err == nil && t != nil {
			tag = t
		}
	}

	if tag == nil {
		return nil, errors.New("failed to create the edge tag")
	}
	return tag, nil
}

// CreateEdgeProperty creates a new edge tag in the database.
// It takes an oam.Property as input and persists it in the database.
// The property is serialized to JSON and stored in the Content field of the EdgeTag struct.
// Returns the created edge tag as a types.EdgeTag or an error if the creation fails.
func (neo *neoRepository) CreateEdgeProperty(edge *types.Edge, prop oam.Property) (*types.EdgeTag, error) {
	return neo.CreateEdgeTag(edge, &types.EdgeTag{Property: prop})
}

func (neo *neoRepository) uniqueEdgeTagID() string {
	for {
		id := uuid.New().String()
		if _, err := neo.FindEdgeTagById(id); err != nil {
			return id
		}
	}
}

// FindEdgeTagById finds an edge tag in the database by the ID.
// It takes a string representing the edge tag ID and retrieves the corresponding tag from the database.
// Returns the discovered tag as a types.EdgeTag or an error if the asset is not found.
func (neo *neoRepository) FindEdgeTagById(id string) (*types.EdgeTag, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := neo4jdb.ExecuteQuery(ctx, neo.db,
		"MATCH (p:EdgeTag {tag_id: $tid}) RETURN p",
		map[string]interface{}{"tid": id},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)
	if err != nil {
		return nil, err
	}
	if len(result.Records) == 0 {
		return nil, fmt.Errorf("the edge tag with ID %s was not found", id)
	}

	node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "p")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the node is nil")
	}
	return nodeToEdgeTag(node)
}

// FindEdgeTagsByContent finds edge tags in the database that match the provided property data and updated_at after the since parameter.
// It takes an oam.Property as input and searches for edge tags with matching content in the database.
// If since.IsZero(), the parameter will be ignored.
// The property data is serialized to JSON and compared against the Content field of the EdgeTag struct.
// Returns a slice of matching edge tags as []*types.EdgeTag or an error if the search fails.
func (neo *neoRepository) FindEdgeTagsByContent(prop oam.Property, since time.Time) ([]*types.EdgeTag, error) {
	qnode, err := queryNodeByPropertyKeyValue("p", "EdgeTag", prop)
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
		return nil, errors.New("no edge tags found")
	}

	node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](result.Records[0], "p")
	if err != nil {
		return nil, err
	}
	if isnil {
		return nil, errors.New("the record value for the node is nil")
	}

	tag, err := nodeToEdgeTag(node)
	if err != nil {
		return nil, err
	}
	return []*types.EdgeTag{tag}, nil
}

// GetEdgeTags finds all tags for the edge with the specified names and last seen after the since parameter.
// If since.IsZero(), the parameter will be ignored.
// If no names are specified, all tags for the specified edge are returned.
func (neo *neoRepository) GetEdgeTags(edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {
	query := fmt.Sprintf("MATCH (p:EdgeTag {edge_id: '%s'}) RETURN p", edge.ID)
	if !since.IsZero() {
		query = fmt.Sprintf("MATCH (p:EdgeTag {edge_id: '%s'}) WHERE p.updated_at >= localDateTime('%s') RETURN p", edge.ID, timeToNeo4jTime(since))
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
		return nil, errors.New("no edge tags found")
	}

	var results []*types.EdgeTag
	for _, record := range result.Records {
		node, isnil, err := neo4jdb.GetRecordValue[neo4jdb.Node](record, "p")
		if err != nil {
			continue
		}
		if isnil {
			continue
		}

		tag, err := nodeToEdgeTag(node)
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

// DeleteEdgeTag removes an edge tag in the database by its ID.
// It takes a string representing the edge tag ID and removes the corresponding tag from the database.
// Returns an error if the tag is not found.
func (neo *neoRepository) DeleteEdgeTag(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := neo4jdb.ExecuteQuery(ctx, neo.db,
		"MATCH (n:EdgeTag {tag_id: $tid}) DETACH DELETE n",
		map[string]interface{}{
			"tid": id,
		},
		neo4jdb.EagerResultTransformer,
		neo4jdb.ExecuteQueryWithDatabase(neo.dbname),
	)

	return err
}
