// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
)

func TestCollectionRunValidate(t *testing.T) {
	var nilRun *CollectionRun
	for name, c := range map[string]struct {
		run *CollectionRun
		ok  bool
	}{
		"nil":            {nilRun, false},
		"no tool":        {&CollectionRun{Tool: "  "}, false},
		"tool only":      {&CollectionRun{Tool: "amass"}, true},
		"valid scope":    {&CollectionRun{Tool: "amass", Scope: []RunTarget{{Type: oam.FQDN, Key: "example.com"}}}, true},
		"unknown type":   {&CollectionRun{Tool: "amass", Scope: []RunTarget{{Type: "Domain", Key: "example.com"}}}, false},
		"empty key":      {&CollectionRun{Tool: "amass", Scope: []RunTarget{{Type: oam.Netblock, Key: " "}}}, false},
		"one bad target": {&CollectionRun{Tool: "amass", Scope: []RunTarget{{Type: oam.FQDN, Key: "example.com"}, {Type: oam.FQDN}}}, false},
	} {
		if err := c.run.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: Validate() = %v, want ok %v", name, err, c.ok)
		}
	}
}

func TestFinalRunStatus(t *testing.T) {
	for status, final := range map[string]bool{
		RunRunning: false, RunFinished: true, RunStopped: true, RunFailed: true, "": false, "Finished": false,
	} {
		if got := FinalRunStatus(status); got != final {
			t.Errorf("FinalRunStatus(%q) = %v, want %v", status, got, final)
		}
	}
}

func TestValidAssetTypeCoversTheModel(t *testing.T) {
	for _, a := range oam.AssetList {
		if !validAssetType(a) {
			t.Errorf("%s is not accepted as a scope target type", a)
		}
	}
}

// Callers and backends pass the blocking keys by value, so adding one must
// not renumber the others.
func TestCoKeyValues(t *testing.T) {
	for want, k := range []CoKey{CoKeyIdentifier, CoKeyContactRecord, CoKeyRegistration, CoKeyTag, CoKeyStreetAddress} {
		if int(k) != want {
			t.Errorf("CoKey %d has value %d", want, k)
		}
	}
}
