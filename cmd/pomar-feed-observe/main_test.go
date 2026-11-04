package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestObserverCommandActualFilesAndRedirectRefusal(t *testing.T) {
	d := t.TempDir()
	artifact := []byte("artifact bytes")
	sum := sha256.Sum256(artifact)
	h := hex.EncodeToString(sum[:])
	head := "1111111111111111111111111111111111111111"
	m := map[string]any{"schema": "zeoconnect-release/1", "repository": "rodriveracom/zeoconnect", "commit": head, "sequence": 140, "artifacts": map[string]any{"example.whl": map[string]any{"bytes": len(artifact), "sha256": h}}}
	manifest, _ := json.Marshal(m)
	for n, b := range map[string][]byte{"release.json": manifest, "example.whl": artifact, "SHA256SUMS": []byte(h + "  example.whl\n")} {
		if e := os.WriteFile(filepath.Join(d, n), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	args := []string{"-inputs", d, "-head", head, "-tree", "2222222222222222222222222222222222222222", "-owner-message", "owner-receipt"}
	var out bytes.Buffer
	if e := run(args, &out); e != nil || !bytes.Contains(out.Bytes(), []byte(`"build_qualification":false`)) {
		t.Fatal(e, out.String())
	}
	if e := os.Rename(filepath.Join(d, "example.whl"), filepath.Join(d, "hidden")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("hidden", filepath.Join(d, "example.whl")); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e := run(args, &out); e == nil || out.Len() != 0 {
		t.Fatal("redirect admitted")
	}
}
