// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package urlkey gives the form a URL is stored and compared in. Only a
// URL's scheme and host are case-insensitive (RFC 3986 section 6.2.2.1), so
// only they are lowercased: the user information, path, query and fragment
// keep their case, since a path, a pre-signed link or a token in a query
// string means something else in another case.
package urlkey

import (
	"net/url"
	"strings"
)

// Key is raw with its scheme and host in lower case and the rest as given.
// A string that does not parse as a URL with a host is kept as given.
func Key(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	prefix := len(u.Scheme) + len("://")
	if len(raw) < prefix || !strings.EqualFold(raw[:prefix], u.Scheme+"://") {
		return raw
	}
	rest := raw[prefix:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	// the host follows any user information, which keeps its case
	userinfo, host := "", authority
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		userinfo, host = authority[:i+1], authority[i+1:]
	}
	return strings.ToLower(u.Scheme) + "://" + userinfo + strings.ToLower(host) + rest[end:]
}
