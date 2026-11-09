// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitestfixture

import (
 "context"
 "path/filepath"
 "testing"
)

func TestSemanticAlternateRouteFixtureLoadsAndSeeds(t *testing.T){
 dir:=filepath.Join(fixtureDir(),"semantic")
 f,err:=Load(dir)
 if err!=nil{t.Fatal(err)}
 if len(f.Assets)!=11 || len(f.Relations)!=10 || len(f.Properties)!=11{
  t.Fatalf("unexpected semantic fixture counts: assets=%d relations=%d properties=%d",len(f.Assets),len(f.Relations),len(f.Properties))
 }
 fromTo:=map[string]int{}
 for _,r:=range f.Relations{fromTo[r.From+"->"+r.To]++}
 if fromTo["url-tech-main->fqdn-tech"]!=1 || fromTo["url-tech-alternate->fqdn-tech"]!=1{
  t.Fatal("expected independent synthetic URL routes to one FQDN")
 }
 sources:=map[string]map[string]bool{}
 for _,p:=range f.Properties {
  if p.Scope!="relation"||p.Kind!="source"{continue}
  if sources[p.Target]==nil{sources[p.Target]=map[string]bool{}}
  sources[p.Target][p.Name]=true
 }
 if len(sources["edge-parent-tech"])!=2||len(sources["edge-parent-europe"])!=1||len(sources["edge-tech-web-main"])!=1||len(sources["edge-tech-web-alternate"])!=2{
  t.Fatalf("source contrast scenario missing: %+v",sources)
 }
 db:=&recordingWriter{}
 report,err:=Seed(context.Background(),db,f)
 if err!=nil{t.Fatal(err)}
 if report.Assets!=11||report.Relations!=10||report.Properties!=11{
  t.Fatalf("seed count mismatch: %+v",report)
 }
 t.Logf("semantic fixture assets=%d relations=%d properties=%d; alternate URL paths and uneven source-tag support",report.Assets,report.Relations,report.Properties)
}
