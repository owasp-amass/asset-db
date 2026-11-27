// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
	"strings"
)

// MaxDegreeLabels is the most relation labels one degree read counts.
const MaxDegreeLabels = 64

// DegreeHistogram is, for one relation label, how many entities have each
// number of edges with the label: degree -> entities.
type DegreeHistogram map[int]int64

// ValidateDegreeRead checks a degree read: a direction of "in" or "out", and
// 1..MaxDegreeLabels labels, none empty.
func ValidateDegreeRead(direction string, labels []string) error {
	if direction != "in" && direction != "out" {
		return errors.New("a degree read counts edges \"in\" or \"out\"")
	}
	if len(labels) == 0 || len(labels) > MaxDegreeLabels {
		return fmt.Errorf("a degree read names 1 to %d relation labels", MaxDegreeLabels)
	}
	for _, l := range labels {
		if strings.TrimSpace(l) == "" {
			return errors.New("a degree read's relation labels are not empty")
		}
	}
	return nil
}
