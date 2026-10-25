package main

// sow: pomar-SOW-87 rev27.
import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPostgresCLIRequiresExplicitBindingsAndUniqueExtensions(t *testing.T) {
	for _, args := range [][]string{{"postgres"}, {"postgres", "run"}, {"postgres", "run", "-extension", "uuid-ossp"}, {"postgres", "run", "-extension", "uuid-ossp@1.1", "-extension", "uuid-ossp@1.1"}} {
		var out, err bytes.Buffer
		if code := run(args, &out, &err); code != 2 {
			t.Fatal(args, code, out.String(), err.String())
		}
	}
}
func TestPostgresCLIRefusalHasStructuredResultAndNoGate(t *testing.T) {
	var out, err bytes.Buffer
	code := run([]string{"postgres", "run", "-work-root", "/nonexistent-pg-fixture", "-tools", "/nonexistent-manifest", "-tools-sha256", strings.Repeat("a", 64), "-cwd", "/nonexistent-gate", "--", "/usr/bin/true"}, &out, &err)
	var r struct{ Root, Error string }
	if code != 1 || json.Unmarshal(out.Bytes(), &r) != nil || r.Error == "" || r.Root != "" {
		t.Fatal(code, out.String(), err.String())
	}
}
