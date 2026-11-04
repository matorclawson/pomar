package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedissuer"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedobserver"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedwire"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func TestFixedIssuerDurableIntentAndSeparateRehearsal(t *testing.T) {
	c := testConfig(t)
	c.keyID = releasefeedissuer.RehearsalKeyID // PUBLIC TEST ONLY
	var pub bytes.Buffer
	if e := run(c, "generate", &pub); e != nil {
		t.Fatal(e)
	}
	var record publicRecord
	if json.Unmarshal(pub.Bytes(), &record) != nil {
		t.Fatal("public record")
	}
	base, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(base, 0755); e != nil {
		t.Fatal(e)
	}
	for _, lane := range []string{"entries", "trust", "rehearsal"} {
		if e := os.Mkdir(filepath.Join(base, lane), 0755); e != nil {
			t.Fatal(e)
		}
	}
	input := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	head := "1111111111111111111111111111111111111111"
	tree := "2222222222222222222222222222222222222222"
	artifact := []byte("public synthetic test artifact")
	manifest, _ := json.Marshal(map[string]any{"schema": "zeoconnect-release/1", "repository": "rodriveracom/zeoconnect", "commit": head, "sequence": 140, "artifacts": map[string]any{"example.whl": map[string]any{"bytes": len(artifact), "sha256": testHash(artifact)}}})
	files := map[string][]byte{"release.json": manifest, "example.whl": artifact, "SHA256SUMS": []byte(testHash(artifact) + "  example.whl\n")}
	receipt, e := releasefeedobserver.Observe(releasefeedobserver.Context{Head: head, Tree: tree, SourceOwnerMessage: "public-test-owner", ObservedAt: now}, files)
	if e != nil {
		t.Fatal(e)
	}
	receipt = append(receipt, '\n') // exact stdout form of observer command
	cclaims := releasefeedwire.Claims{KeyID: c.keyID, Head: head, Tree: tree, Sequence: 140, IssuedAt: now.Format("2006-01-02T15:04:05Z"), ExpiresAt: now.Add(time.Hour).Format("2006-01-02T15:04:05Z"), ReceiptRef: "test-receipt", TargetProfile: "test-profile", TargetDigest: testHash([]byte("test-target")), ProfileGeneration: 1, PolicyGeneration: 1, TrustGeneration: 1, RevocationGeneration: 1}
	policy := releasefeedissuer.Policy{Schema: "pomar.feed-issuance-policy/v1", Purpose: "rehearsal", Claims: cclaims, PublicKeySHA256: record.Fingerprint, ReceiptSHA256: testHash(receipt), Files: map[string]string{}, SuccessorDueAt: now.Add(30 * time.Minute).Format("2006-01-02T15:04:05Z")}
	for n, b := range files {
		policy.Files[n] = testHash(b)
		if e := os.WriteFile(filepath.Join(input, n), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(input, "receipt.json"), receipt, 0600); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(issuanceInput{policy, input})
	if e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(c.home)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	var out bytes.Buffer
	if e := issueAuthenticated(c, root, raw, base, &out); e != nil {
		t.Fatal(e)
	}
	entry := "000140-111111111111"
	if _, e := os.Stat(filepath.Join(base, "entries", entry)); !os.IsNotExist(e) {
		t.Fatal("rehearsal entered production")
	}
	for _, n := range []string{"sequence-000140.intent.json", "sequence-000140.signed.attestation", "sequence-000140.complete.json"} {
		if _, e := os.Stat(filepath.Join(c.home, n)); e != nil {
			t.Fatal(e)
		}
	}
	if e := issueAuthenticated(c, root, raw, base, &out); e == nil {
		t.Fatal("sequence replay allowed")
	}
	if _, e := os.Stat(filepath.Join(c.home, "issuance.lock")); e != nil {
		t.Fatal("unknown retry lock not retained")
	}
	if _, e := protectedPolicy(filepath.Join(input, "receipt.json")); e == nil {
		t.Fatal("seat-writable policy accepted")
	}
}
func TestTrustRefusesRehearsalIdentity(t *testing.T) {
	if _, e := trustBytes(publicRecord{KeyID: releasefeedissuer.RehearsalKeyID}); e == nil {
		t.Fatal("rehearsal trusted")
	}
}
