// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package valuequery

import (
	"strings"
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
)

func TestCheck(t *testing.T) {
	for name, c := range map[string]struct {
		atype oam.AssetType
		key   string
		value string
		limit int
		ok    bool
	}{
		"valid":           {oam.FQDN, "name", "example.com", 10, true},
		"max limit":       {oam.FQDN, "name", "example.com", MaxLimit, true},
		"no type":         {" ", "name", "example.com", 10, false},
		"no name":         {oam.FQDN, "", "example.com", 10, false},
		"long name":       {oam.FQDN, strings.Repeat("n", 129), "example.com", 10, false},
		"no value":        {oam.FQDN, "name", "", 10, false},
		"long value":      {oam.FQDN, "name", strings.Repeat("v", 1025), 10, false},
		"zero limit":      {oam.FQDN, "name", "example.com", 0, false},
		"limit too large": {oam.FQDN, "name", "example.com", MaxLimit + 1, false},
	} {
		if err := Check(c.atype, c.key, c.value, c.limit); (err == nil) != c.ok {
			t.Errorf("%s: Check() = %v, want ok %v", name, err, c.ok)
		}
	}
}

func TestCheckKey(t *testing.T) {
	for key, ok := range map[string]bool{
		"name": true, "id_type": true, "a1": true, strings.Repeat("a", 64): true,
		"": false, "Name": false, "1name": false, "_name": false, "na-me": false, "name'": false,
		"name; DROP": false, strings.Repeat("a", 65): false,
	} {
		if err := CheckKey(key); (err == nil) != ok {
			t.Errorf("CheckKey(%q) = %v, want ok %v", key, err, ok)
		}
	}
}

func TestLikePattern(t *testing.T) {
	for value, want := range map[string]string{
		"Example.COM": "%example.com%",
		"50%_off":     `%50\%\_off%`,
		`a\b`:         `%a\\b%`,
		"":            "%%",
	} {
		if got := LikePattern(value); got != want {
			t.Errorf("LikePattern(%q) = %q, want %q", value, got, want)
		}
	}
}
