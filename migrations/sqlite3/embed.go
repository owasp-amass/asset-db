// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"embed"
)

//go:embed *.sql
var sqlite3Migrations embed.FS

func Migrations() embed.FS {
	return sqlite3Migrations
}
