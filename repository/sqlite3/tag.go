// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

func extractOAMProperty(ttype string, content []byte) (oam.Property, error) {
	err := errors.New("failed to extract property from the JSON")

	if len(content) == 0 {
		return nil, err
	}

	var p oam.Property
	switch strings.ToLower(ttype) {
	case strings.ToLower(string(oam.DNSRecordProperty)):
		var dp oamdns.DNSRecordProperty
		if e := json.Unmarshal(content, &dp); e == nil {
			p = &dp
			err = nil
		}
	case strings.ToLower(string(oam.SimpleProperty)):
		var sp oamgen.SimpleProperty
		if e := json.Unmarshal(content, &sp); e == nil {
			p = &sp
			err = nil
		}
	case strings.ToLower(string(oam.SourceProperty)):
		var sp oamgen.SourceProperty
		if e := json.Unmarshal(content, &sp); e == nil {
			p = &sp
			err = nil
		}
	case strings.ToLower(string(oam.VulnProperty)):
		var vp oamplat.VulnProperty
		if e := json.Unmarshal(content, &vp); e == nil {
			p = &vp
			err = nil
		}
	default:
		return nil, fmt.Errorf("unknown property type: %s", ttype)
	}

	return p, err
}
