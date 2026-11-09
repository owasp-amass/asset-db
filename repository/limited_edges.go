// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"github.com/owasp-amass/asset-db/types"
	"time"
)

// LimitedEdgeReader is an optional read-only repository capability.
// Unlike IncomingEdges/OutgoingEdges it limits rows at the database layer.
// A returned more=true means at least one further matching edge exists.
// Pagination with a stable cursor may be added later; this API returns only
// the first page in latest-observation order.
type LimitedEdgeReader interface {
	ReadEdgesLimited(ctx context.Context, entity *types.Entity, direction string, since time.Time, limit int, labels ...string) ([]*types.Edge, bool, error)
}
