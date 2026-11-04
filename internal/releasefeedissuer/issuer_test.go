package releasefeedissuer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedobserver"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedwire"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T) (Policy, []byte, map[string][]byte, ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 4, 4, 0, 0, 0, time.UTC)
	head := "1111111111111111111111111111111111111111"
	tree := "2222222222222222222222222222222222222222"
	artifact := []byte("public synthetic test artifact")
	h := hash(artifact)
	manifest, _ := json.Marshal(map[string]any{"schema": "zeoconnect-release/1", "repository": "rodriveracom/zeoconnect", "commit": head, "sequence": 140, "artifacts": map[string]any{"example.whl": map[string]any{"bytes": len(artifact), "sha256": h}}})
	files := map[string][]byte{"release.json": manifest, "example.whl": artifact, "SHA256SUMS": []byte(h + "  example.whl\n")}
	receipt, e := releasefeedobserver.Observe(releasefeedobserver.Context{Head: head, Tree: tree, SourceOwnerMessage: "test-owner-message", ObservedAt: now}, files)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)) // PUBLIC TEST ONLY
	c := releasefeedwire.Claims{KeyID: RehearsalKeyID, IssuedAt: "2026-11-04T04:00:00Z", ExpiresAt: "2026-11-05T04:00:00Z", Head: head, Tree: tree, ReceiptRef: "test-receipt-140", TargetProfile: "test-profile", TargetDigest: hash([]byte("public test target")), Sequence: 140, ProfileGeneration: 1, PolicyGeneration: 1, TrustGeneration: 1, RevocationGeneration: 1}
	p := Policy{Schema: "pomar.feed-issuance-policy/v1", Purpose: "rehearsal", Claims: c, PublicKeySHA256: hash(key.Public().(ed25519.PublicKey)), ReceiptSHA256: hash(receipt), Files: map[string]string{}, SuccessorDueAt: "2026-11-05T03:00:00Z"}
	for n, b := range files {
		p.Files[n] = hash(b)
	}
	return p, receipt, files, key, now
}
func TestPolicyBuildAndA1A2Refusals(t *testing.T) {
	p, r, f, k, now := fixture(t)
	b, e := Build(p, r, f, k, now)
	if e != nil || b.Purpose != "rehearsal" {
		t.Fatal(e)
	}
	prepared, e := releasefeedwire.Prepare(p.Claims, f["release.json"], r)
	if e != nil {
		t.Fatal(e)
	}
	want, e := prepared.Attestation(ed25519.Sign(k, prepared.SigningBytes()))
	if e != nil || !bytes.Equal(want, b.Files["attestation.bin"]) {
		t.Fatal("signature mismatch")
	}
	for _, kind := range []string{"production-key-rehearsal", "rehearsal-key-production", "expiry", "future", "successor", "receipt", "artifact", "public-key"} {
		t.Run(kind, func(t *testing.T) {
			p, r, f, k, n := fixture(t)
			switch kind {
			case "production-key-rehearsal":
				p.Claims.KeyID = ProductionKeyID
			case "rehearsal-key-production":
				p.Purpose = "production"
			case "expiry":
				n = n.Add(24 * time.Hour)
			case "future":
				n = n.Add(-301 * time.Second)
			case "successor":
				p.SuccessorDueAt = p.Claims.IssuedAt
			case "receipt":
				r[0] ^= 1
			case "artifact":
				f["example.whl"][0] ^= 1
			case "public-key":
				p.PublicKeySHA256 = hash([]byte("wrong"))
			}
			if _, e := Build(p, r, f, k, n); e == nil {
				t.Fatal("policy drift accepted")
			}
		})
	}
}
func publicRoot(t *testing.T) string {
	t.Helper()
	d, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(d, 0755); e != nil {
		t.Fatal(e)
	}
	for _, lane := range []string{"entries", "rehearsal", "trust"} {
		if e := os.Mkdir(filepath.Join(d, lane), 0755); e != nil {
			t.Fatal(e)
		}
	}
	return d
}
func TestAtomicRehearsalLaneAndNeverReplace(t *testing.T) {
	p, r, f, k, n := fixture(t)
	b, e := Build(p, r, f, k, n)
	if e != nil {
		t.Fatal(e)
	}
	base := publicRoot(t)
	if e := Publish(base, os.Getuid(), b); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(base, "entries", b.EntryID)); !os.IsNotExist(e) {
		t.Fatal("rehearsal exposed to production")
	}
	before, e := os.ReadFile(filepath.Join(base, "rehearsal", b.EntryID, "attestation.bin"))
	if e != nil {
		t.Fatal(e)
	}
	b.Files["attestation.bin"] = []byte("replacement")
	if e := Publish(base, os.Getuid(), b); e == nil {
		t.Fatal("replacement permitted")
	}
	after, e := os.ReadFile(filepath.Join(base, "rehearsal", b.EntryID, "attestation.bin"))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("original changed")
	}
}
func TestA3ModesSymlinksAndUnknownPredecessorRefused(t *testing.T) {
	for _, kind := range []string{"writable", "symlink", "held"} {
		t.Run(kind, func(t *testing.T) {
			base := publicRoot(t)
			p, r, f, k, n := fixture(t)
			b, e := Build(p, r, f, k, n)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "writable":
				if e := os.Chmod(filepath.Join(base, "trust"), 0777); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(filepath.Join(base, "entries"), filepath.Join(base, "old")); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("old", filepath.Join(base, "entries")); e != nil {
					t.Fatal(e)
				}
			case "held":
				if e := os.WriteFile(filepath.Join(base, ".publication.lock"), []byte("unknown predecessor"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e := Publish(base, os.Getuid(), b); e == nil {
				t.Fatal("unsafe publication allowed")
			}
		})
	}
}

func TestPublicEntryReadableUnderPrivateUmask(t *testing.T) {
	p, r, f, k, n := fixture(t)
	b, e := Build(p, r, f, k, n)
	if e != nil {
		t.Fatal(e)
	}
	base := publicRoot(t)
	old := syscall.Umask(0077)
	defer syscall.Umask(old)
	if e := Publish(base, os.Getuid(), b); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(base, "rehearsal", b.EntryID)
	info, e := os.Stat(dir)
	if e != nil || info.Mode().Perm() != 0755 {
		t.Fatal("private umask made public entry unreadable", e)
	}
	for name := range b.Files {
		info, e := os.Stat(filepath.Join(dir, name))
		if e != nil || info.Mode().Perm() != 0644 {
			t.Fatal("public file mode differs", e)
		}
	}
}
