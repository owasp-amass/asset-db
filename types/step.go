// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"strings"
)

// MaxSteps bounds the steps one step read takes.
const MaxSteps = 512

// Step is one way a walk over the graph moves from an entity to a neighbor:
// along an edge of RelationType (an OAM relation type, such as
// SimpleRelation) labeled Label, from an entity of FromType to one of ToType
// (OAM asset types). Forward steps move from the edge's source to its
// destination; the others move from the destination back to the source. A
// port relation's label is "port". Names compare without case.
type Step struct {
	FromType     string `json:"from_type"`
	Label        string `json:"label"`
	RelationType string `json:"relation_type"`
	ToType       string `json:"to_type"`
	Forward      bool   `json:"forward"`
}

// Key is the step with its names lower-cased, as step reads compare them.
func (s Step) Key() Step {
	return Step{FromType: strings.ToLower(s.FromType), Label: strings.ToLower(s.Label),
		RelationType: strings.ToLower(s.RelationType), ToType: strings.ToLower(s.ToType), Forward: s.Forward}
}

// CheckSteps validates the steps of one step read and returns them by
// direction, lower-cased and without duplicates.
func CheckSteps(steps []Step) (forward, backward []Step, err error) {
	if len(steps) == 0 || len(steps) > MaxSteps {
		return nil, nil, errors.New("a step read takes 1..512 steps")
	}

	seen := make(map[Step]bool, len(steps))
	for _, s := range steps {
		k := s.Key()
		if k.FromType == "" || k.Label == "" || k.RelationType == "" || k.ToType == "" ||
			len(k.FromType)+len(k.Label)+len(k.RelationType)+len(k.ToType) > 512 {
			return nil, nil, errors.New("a step names its from type, label, relation type and to type")
		}
		if seen[k] {
			continue
		}

		seen[k] = true
		if k.Forward {
			forward = append(forward, k)
		} else {
			backward = append(backward, k)
		}
	}
	return forward, backward, nil
}
