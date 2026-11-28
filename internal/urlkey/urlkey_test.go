// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package urlkey

import "testing"

func TestKey(t *testing.T) {
	for in, want := range map[string]string{
		"HTTP://User:PW@Host.Example:8080/A?B=C#D": "http://User:PW@host.example:8080/A?B=C#D",
		"https://Example.com":                      "https://example.com",
		"https://example.com/Reports/Q1.PDF":       "https://example.com/Reports/Q1.PDF",
		"/local/Path/File.PDF":                     "/local/Path/File.PDF",
		"not a url":                                "not a url",
	} {
		if got := Key(in); got != want {
			t.Errorf("Key(%q) = %q, want %q", in, got, want)
		}
	}
}
