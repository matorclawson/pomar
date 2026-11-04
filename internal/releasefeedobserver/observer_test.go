package releasefeedobserver

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func fixture(t *testing.T) (Context, map[string][]byte) {
	t.Helper()
	b := []byte("actual artifact")
	h := digest(b)
	m := map[string]any{"schema": "zeoconnect-release/1", "repository": "rodriveracom/zeoconnect", "commit": "1111111111111111111111111111111111111111", "sequence": 140, "artifacts": map[string]any{"sample.whl": map[string]any{"bytes": len(b), "sha256": h}}}
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	return Context{Head: m["commit"].(string), Tree: "2222222222222222222222222222222222222222", SourceOwnerMessage: "owner-message", ObservedAt: time.Date(2026, 11, 4, 3, 0, 0, 0, time.UTC)}, map[string][]byte{"release.json": raw, "sample.whl": b, "SHA256SUMS": []byte(h + "  sample.whl\n")}
}
func TestObservationNeverInventsQualification(t *testing.T) {
	c, f := fixture(t)
	raw, e := Observe(c, f)
	if e != nil {
		t.Fatal(e)
	}
	var r Receipt
	if json.Unmarshal(raw, &r) != nil || r.BuildQualification || r.DeploymentIndependentlyObserved || len(r.Files) != 3 || r.Sequence != 140 {
		t.Fatal("false observation", string(raw))
	}
	f["sample.whl"][0] ^= 1
	if !bytes.Contains(raw, []byte(digest([]byte("actual artifact")))) {
		t.Fatal("receipt aliases input")
	}
}
func TestRefuseChangedMissingExtraAndUnsupportedInputs(t *testing.T) {
	for _, kind := range []string{"bytes", "missing", "extra", "checksum", "duplicate", "head", "schema", "time"} {
		t.Run(kind, func(t *testing.T) {
			c, f := fixture(t)
			switch kind {
			case "bytes":
				f["sample.whl"][0] ^= 1
			case "missing":
				delete(f, "sample.whl")
			case "extra":
				f["surprise"] = []byte("x")
			case "checksum":
				f["SHA256SUMS"] = []byte("bad")
			case "duplicate":
				f["SHA256SUMS"] = append(f["SHA256SUMS"], f["SHA256SUMS"]...)
			case "head":
				c.Head = "3333333333333333333333333333333333333333"
			case "schema":
				f["release.json"] = bytes.ReplaceAll(f["release.json"], []byte("release/1"), []byte("release/2"))
			case "time":
				c.ObservedAt = time.Time{}
			}
			if raw, e := Observe(c, f); e == nil || raw != nil {
				t.Fatal("unobserved input accepted")
			}
		})
	}
}
