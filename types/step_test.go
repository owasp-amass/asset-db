// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import "testing"

func TestCheckSteps(t *testing.T) {
	a := Step{FromType: "FQDN", Label: "node", RelationType: "SimpleRelation", ToType: "FQDN", Forward: true}
	b := Step{FromType: "fqdn", Label: "NODE", RelationType: "simplerelation", ToType: "fqdn", Forward: true}
	c := Step{FromType: "Organization", Label: "subsidiary", RelationType: "SimpleRelation", ToType: "Organization"}

	fwd, back, err := CheckSteps([]Step{a, b, c})
	if err != nil || len(fwd) != 1 || len(back) != 1 || fwd[0].Label != "node" || back[0].FromType != "organization" {
		t.Errorf("CheckSteps = %+v, %+v, %v", fwd, back, err)
	}
	if _, _, err := CheckSteps(nil); err == nil {
		t.Error("no steps were accepted")
	}
	if _, _, err := CheckSteps([]Step{{FromType: "FQDN", Label: "node"}}); err == nil {
		t.Error("a step without its relation and to types was accepted")
	}
	if _, _, err := CheckSteps(make([]Step, MaxSteps+1)); err == nil {
		t.Error("too many steps were accepted")
	}
}
