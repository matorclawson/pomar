package main

import (
	"encoding/json"
	"testing"
)

func TestClosedPrivateSiteBinding(t *testing.T) {
	good := map[string]any{"schema": "pomar.feed-site-binding/v1", "hostname": "test-host", "public_base": "/var/tmp/pomar-feed-public-test"}
	raw, _ := json.Marshal(good)
	s, e := parseSiteBinding(raw)
	if e != nil || s.Hostname != "test-host" {
		t.Fatal(e)
	}
	for _, kind := range []string{"unknown", "hostname", "schema", "relative", "private", "private-child", "root", "unclean"} {
		t.Run(kind, func(t *testing.T) {
			m := map[string]any{}
			for k, v := range good {
				m[k] = v
			}
			switch kind {
			case "unknown":
				m["private_seed"] = "forbidden"
			case "hostname":
				m["hostname"] = "host/redirect"
			case "schema":
				m["schema"] = "wrong"
			case "relative":
				m["public_base"] = "relative"
			case "private":
				m["public_base"] = custodyHome
			case "private-child":
				m["public_base"] = custodyHome + "/rehearsal"
			case "root":
				m["public_base"] = "/"
			case "unclean":
				m["public_base"] = "/var/tmp/../tmp/feed"
			}
			b, _ := json.Marshal(m)
			if _, e := parseSiteBinding(b); e == nil {
				t.Fatal("invalid site binding accepted")
			}
		})
	}
}
