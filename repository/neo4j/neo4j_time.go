// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package neo4j

import (
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
)

func neo4jTimeToTime(neot dbtype.LocalDateTime) time.Time {
	t := neot.Time()
	t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
	return t.Local()
}

func timeToNeo4jTime(t time.Time) dbtype.LocalDateTime {
	t = t.UTC()
	t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
	return dbtype.LocalDateTime(t)
}
