// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package triples

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type Results struct {
	Node *Vertex `json:"entity"`
}

type Vertex struct {
	entity     *dbt.Entity   `json:"-"`
	ID         string        `json:"id"`
	Type       oam.AssetType `json:"type"`
	CreatedAt  string        `json:"created_at"`
	LastSeen   string        `json:"last_seen"`
	Asset      oam.Asset     `json:"asset"`
	Relations  []*Link       `json:"edges"`
	Properties []*Prop       `json:"tags"`
}

type Link struct {
	ID         string           `json:"id"`
	Type       oam.RelationType `json:"type"`
	CreatedAt  string           `json:"created_at"`
	LastSeen   string           `json:"last_seen"`
	Relation   oam.Relation     `json:"relation"`
	Node       *Vertex          `json:"entity"`
	Properties []*Prop          `json:"tags"`
}

type Prop struct {
	ID        string           `json:"id"`
	Type      oam.PropertyType `json:"type"`
	CreatedAt string           `json:"created_at"`
	LastSeen  string           `json:"last_seen"`
	Property  oam.Property     `json:"property"`
}

func Extract(db repository.Repository, triples []*Triple) (*Results, error) {
	if len(triples) == 0 {
		return nil, errors.New("no triples provided for extraction")
	}

	ent, err := findFirstSubject(db, triples[0].Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to find first subject: %w", err)
	}

	n := &Vertex{
		entity:    ent,
		ID:        ent.ID,
		Type:      ent.Asset.AssetType(),
		CreatedAt: ent.CreatedAt.Format(time.DateOnly),
		LastSeen:  ent.LastSeen.Format(time.DateOnly),
		Asset:     ent.Asset,
		Relations: []*Link{},
	}

	rels, err := performWalk(db, triples, 0, []*Link{{Node: n}})
	if err != nil {
		return nil, err
	}
	if len(rels) != 1 {
		return nil, errors.New("failed to extract the walk from the first subject")
	}

	return &Results{Node: n}, nil
}

func performWalk(db repository.Repository, triples []*Triple, idx int, links []*Link) ([]*Link, error) {
	var rels []*Link
	triple := triples[idx]

	for _, n := range links {
		ent := n.Node.entity

		// filter based on the entity asset and the triple subject
		if (triple.Subject.Since.IsZero() || !ent.LastSeen.Before(triple.Subject.Since)) &&
			(triple.Subject.Type == "*" || triple.Subject.Type == ent.Asset.AssetType()) &&
			(triple.Subject.Key == "*" || valueMatch(ent.Asset.Key(), triple.Subject.Key,
				triple.Subject.Regexp)) && allAttrsMatch(ent.Asset, triple.Subject.Attributes) {

			if subjectProps, ok := entityPropsMatch(db, ent, triple.Subject.Properties); ok {
				if entRels, err := predAndObject(db, ent, triple); err == nil && len(entRels) > 0 {
					var include bool

					if idx+1 < len(triples) {
						if entRels, err := performWalk(db, triples, idx+1, entRels); err == nil && len(entRels) > 0 {
							include = true // continue walking if there are more triples to process
							n.Node.Relations = append(n.Node.Relations, entRels...)
						}
					} else {
						include = true // last triple, include all relations
						n.Node.Relations = append(n.Node.Relations, entRels...)
					}

					if include {
						rels = append(rels, n)
						n.Node.Properties = subjectProps
					}
				}
			}
		}
	}

	var err error
	if len(rels) == 0 {
		err = errors.New("no walks were successful")
	}
	return rels, err
}

func predAndObject(db repository.Repository, ent *dbt.Entity, triple *Triple) ([]*Link, error) {
	if ent == nil || triple == nil {
		return nil, errors.New("entity or triple cannot be nil")
	}

	var labels []string
	if triple.Predicate.Label != "*" && triple.Predicate.Regexp == nil {
		labels = []string{triple.Predicate.Label}
	}

	var err error
	var edges []*dbt.Edge
	ctx := context.Background()
	if triple.Direction == DirectionIncoming {
		edges, err = db.IncomingEdges(ctx, ent, triple.Predicate.Since, labels...)
	} else {
		edges, err = db.OutgoingEdges(ctx, ent, triple.Predicate.Since, labels...)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get edges for entity %s: %v", ent.ID, err)
	}

	var results []*Link
	for _, edge := range edges {
		// perform filtering based on the predicate in the triple and the edge relation
		if edge != nil && (triple.Predicate.Type == oam.RelationType("*") ||
			triple.Predicate.Type == edge.Relation.RelationType()) && (triple.Predicate.Label == "*" ||
			valueMatch(edge.Relation.Label(), triple.Predicate.Label, triple.Predicate.Regexp)) &&
			allAttrsMatch(edge.Relation, triple.Predicate.Attributes) {
			if linkProps, ok := edgePropsMatch(db, edge, triple.Predicate.Properties); ok {
				var objent *dbt.Entity

				if triple.Direction == DirectionIncoming {
					objent = edge.FromEntity
				} else {
					objent = edge.ToEntity
				}

				if obj, err := db.FindEntityById(ctx, objent.ID); err == nil && obj != nil {
					// perform filtering based on the object in the triple and the entity asset
					if (triple.Object.Since.IsZero() || !obj.LastSeen.Before(triple.Object.Since)) &&
						(triple.Object.Type == "*" || triple.Object.Type == obj.Asset.AssetType()) &&
						(triple.Object.Key == "*" || valueMatch(obj.Asset.Key(), triple.Object.Key,
							triple.Object.Regexp)) && allAttrsMatch(obj.Asset, triple.Object.Attributes) {

						if objectProps, ok := entityPropsMatch(db, obj, triple.Object.Properties); ok {
							results = append(results, &Link{
								ID:        edge.ID,
								Type:      edge.Relation.RelationType(),
								CreatedAt: edge.CreatedAt.Format(time.DateOnly),
								LastSeen:  edge.LastSeen.Format(time.DateOnly),
								Relation:  edge.Relation,
								Node: &Vertex{
									ID:         obj.ID,
									entity:     obj,
									Type:       obj.Asset.AssetType(),
									CreatedAt:  obj.CreatedAt.Format(time.DateOnly),
									LastSeen:   obj.LastSeen.Format(time.DateOnly),
									Asset:      obj.Asset,
									Relations:  []*Link{},
									Properties: objectProps,
								},
								Properties: linkProps,
							})
						}
					}
				}
			}
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no objects found for entity %s with predicate %s", ent.ID, triple.Predicate.Label)
	}
	return results, nil
}

func findFirstSubject(db repository.Repository, subject *Node) (*dbt.Entity, error) {
	if subject == nil {
		return nil, errors.New("subject cannot be nil")
	}

	filter, err := subjectToAsset(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to convert subject to asset: %v", err)
	}

	ent, err := db.FindOneEntityByContent(context.Background(), subject.Type, subject.Since, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find the subject in the database: %v", err)
	}
	return ent, nil
}

func subjectToAsset(subject *Node) (dbt.ContentFilters, error) {
	subtype := string(subject.Type)
	filter := make(dbt.ContentFilters)

	switch {
	case strings.EqualFold(subtype, string(oam.Account)):
		filter["unique_id"] = subject.Key
	case strings.EqualFold(subtype, string(oam.AutnumRecord)):
		filter["handle"] = subject.Key
	case strings.EqualFold(subtype, string(oam.AutonomousSystem)):
		asn, err := strconv.Atoi(subject.Key)
		if err != nil {
			return nil, fmt.Errorf("invalid autonomous system number: %s", subject.Key)
		}
		filter["number"] = asn
	case strings.EqualFold(subtype, string(oam.ContactRecord)):
		filter["discovered_at"] = subject.Key
	case strings.EqualFold(subtype, string(oam.DomainRecord)):
		filter["domain"] = subject.Key
	case strings.EqualFold(subtype, string(oam.File)):
		filter["url"] = subject.Key
	case strings.EqualFold(subtype, string(oam.FQDN)):
		filter["name"] = subject.Key
	case strings.EqualFold(subtype, string(oam.FundsTransfer)):
		filter["unique_id"] = subject.Key
	case strings.EqualFold(subtype, string(oam.Identifier)):
		filter["unique_id"] = subject.Key
	case strings.EqualFold(subtype, string(oam.IPAddress)):
		addr, err := netip.ParseAddr(subject.Key)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address: %s", subject.Key)
		}
		filter["address"] = addr.String()
	case strings.EqualFold(subtype, string(oam.IPNetRecord)):
		filter["handle"] = subject.Key
	case strings.EqualFold(subtype, string(oam.Location)):
		filter["address"] = subject.Key
	case strings.EqualFold(subtype, string(oam.Netblock)):
		prefix, err := netip.ParsePrefix(subject.Key)
		if err != nil {
			return nil, fmt.Errorf("invalid netblock prefix: %s", subject.Key)
		}

		filter["cidr"] = prefix.String()
	case strings.EqualFold(subtype, string(oam.Organization)):
		filter["unique_id"] = subject.Key
	case strings.EqualFold(subtype, string(oam.Person)):
		filter["unique_id"] = subject.Key
	case strings.EqualFold(subtype, string(oam.Phone)):
		filter["raw"] = subject.Key
	case strings.EqualFold(subtype, string(oam.Product)):
		filter["unique_id"] = subject.Key
	case strings.EqualFold(subtype, string(oam.ProductRelease)):
		filter["name"] = subject.Key
	case strings.EqualFold(subtype, string(oam.Service)):
		filter["unique_id"] = subject.Key
	case strings.EqualFold(subtype, string(oam.TLSCertificate)):
		filter["serial_number"] = subject.Key
	case strings.EqualFold(subtype, string(oam.URL)):
		filter["url"] = subject.Key
	default:
		return nil, fmt.Errorf("unknown asset type: %s", subtype)
	}

	return filter, nil
}

func entityPropsMatch(db repository.Repository, ent *dbt.Entity, propstrs []*Property) ([]*Prop, bool) {
	var names []string
	for _, p := range propstrs {
		if p.Name != "*" && p.Regexp == nil {
			names = append(names, p.Name)
		}
	}

	var since time.Time
	for _, p := range propstrs {
		if p.Since.IsZero() {
			continue // skip properties without a since value
		}
		if since.IsZero() || p.Since.Before(since) {
			since = p.Since // find the earliest since value
		}
	}

	tags, err := db.FindEntityTags(context.Background(), ent, since, names...)
	if err != nil || len(tags) == 0 {
		// return an empty slice if no tags are found or an error occurs
		return []*Prop{}, len(propstrs) == 0
	}

	set := stringset.New()
	defer set.Close()

	for _, p := range propstrs {
		pkey := fmt.Sprintf("%s:%s", string(p.Type), p.Name)
		set.Insert(pkey)
	}

	matchedProps := []*Prop{}
	for _, t := range tags {
		if t == nil || t.Property.Name() == "" || t.Property.Value() == "" {
			continue // skip invalid properties
		}

		passed := true
		for _, s := range propstrs {
			if s.Type == t.Property.PropertyType() &&
				(s.Name == "*" || valueMatch(t.Property.Name(), s.Name, s.Regexp)) {
				if !s.Since.IsZero() && t.LastSeen.Before(s.Since) {
					passed = false // property does not match the since value
					break
				}
				if !allAttrsMatch(t.Property, s.Attributes) {
					passed = false // property does not match the attributes
					break
				}
			}
		}

		if passed {
			matchedProps = append(matchedProps, &Prop{
				ID:        t.ID,
				Type:      t.Property.PropertyType(),
				CreatedAt: t.CreatedAt.Format(time.DateOnly),
				LastSeen:  t.LastSeen.Format(time.DateOnly),
				Property:  t.Property,
			})
		}
	}

	return matchedProps, len(matchedProps) >= set.Len()
}

func edgePropsMatch(db repository.Repository, edge *dbt.Edge, propstrs []*Property) ([]*Prop, bool) {
	var names []string
	for _, p := range propstrs {
		if p.Name != "*" && p.Regexp == nil {
			names = append(names, p.Name)
		}
	}

	var since time.Time
	for _, p := range propstrs {
		if p.Since.IsZero() {
			continue // skip properties without a since value
		}
		if since.IsZero() || p.Since.Before(since) {
			since = p.Since // find the earliest since value
		}
	}

	tags, err := db.FindEdgeTags(context.Background(), edge, since, names...)
	if err != nil || len(tags) == 0 {
		// indicate failure if no tags are found or an error occurs
		return []*Prop{}, len(propstrs) == 0
	}

	set := stringset.New()
	defer set.Close()

	for _, p := range propstrs {
		pkey := fmt.Sprintf("%s:%s", string(p.Type), p.Name)
		set.Insert(pkey)
	}

	matchedProps := []*Prop{}
	for _, t := range tags {
		if t == nil || t.Property.Name() == "" || t.Property.Value() == "" {
			continue // skip invalid properties
		}

		passed := true
		for _, s := range propstrs {
			if s.Type == t.Property.PropertyType() &&
				(s.Name == "*" || valueMatch(t.Property.Name(), s.Name, s.Regexp)) {
				if !s.Since.IsZero() && t.LastSeen.Before(s.Since) {
					passed = false // property does not match the since value
					break
				}
				if !allAttrsMatch(t.Property, s.Attributes) {
					passed = false // property does not match the attributes
					break
				}
			}
		}

		if passed {
			matchedProps = append(matchedProps, &Prop{
				ID:        t.ID,
				Type:      t.Property.PropertyType(),
				CreatedAt: t.CreatedAt.Format(time.DateOnly),
				LastSeen:  t.LastSeen.Format(time.DateOnly),
				Property:  t.Property,
			})
		}
	}

	return matchedProps, len(matchedProps) >= set.Len()
}
