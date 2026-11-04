package releasefeedwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func testClaims() Claims {
	return Claims{KeyID: "test-only-not-trusted", IssuedAt: "2026-11-04T00:00:00Z", ExpiresAt: "2026-11-05T00:00:00Z",
		Head: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), Sequence: 7,
		ReceiptRef: "test-receipt-1", TargetProfile: "test-target", TargetDigest: strings.Repeat("c", 64),
		ProfileGeneration: 1, PolicyGeneration: 2, TrustGeneration: 3, RevocationGeneration: 4}
}

func TestIndependentTranscriptAndFraming(t *testing.T) {
	manifest := []byte("{\"test_only\":true}\n")
	receipt := []byte("test-only receipt bytes\n")
	p, err := Prepare(testClaims(), manifest, receipt)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(p.HeaderBytes(), &fields); err != nil {
		t.Fatal(err)
	}
	names := strings.Fields("key_id domain issued_at expires_at repository object_format head tree sequence entry_id manifest_length manifest_sha256 receipt_length receipt_sha256 receipt_ref profile_generation policy_generation target_profile target_digest trust_generation revocation_generation")
	if len(fields) != len(names) {
		t.Fatalf("header keys: %v", fields)
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			t.Fatalf("missing %s", name)
		}
	}
	check := func(name, want string) {
		t.Helper()
		var got string
		if json.Unmarshal(fields[name], &got) != nil || got != want {
			t.Fatalf("%s = %s, want %q", name, fields[name], want)
		}
	}
	check("domain", "pomar-release-entry-v1")
	check("repository", "rodriveracom/zeoconnect")
	check("object_format", "sha1")
	check("entry_id", "000007-aaaaaaaaaaaa")
	for _, item := range []struct {
		name string
		raw  []byte
	}{{"manifest", manifest}, {"receipt", receipt}} {
		sum := sha256.Sum256(item.raw)
		check(item.name+"_sha256", hex.EncodeToString(sum[:]))
		var n int
		if json.Unmarshal(fields[item.name+"_length"], &n) != nil || n != len(item.raw) {
			t.Fatalf("wrong %s length", item.name)
		}
	}
	// Decode the transcript independently, without using the package's encoder.
	input := p.SigningBytes()
	prefix := []byte("pomar-release-entry-v1\x00")
	if !bytes.HasPrefix(input, prefix) {
		t.Fatal("wrong signing domain")
	}
	rest := input[len(prefix):]
	n := int(binary.BigEndian.Uint32(rest[:4]))
	rest = rest[4:]
	if !bytes.Equal(rest[:n], p.HeaderBytes()) {
		t.Fatal("signed header differs from stored bytes")
	}
	rest = rest[n:]
	m := binary.BigEndian.Uint64(rest[:8])
	rest = rest[8:]
	if m != uint64(len(manifest)) || !bytes.Equal(rest, manifest) {
		t.Fatal("wrong exact manifest transcript")
	}
	// Public deterministic TEST-ONLY material, never an operational trust key.
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	sig := ed25519.Sign(key, input)
	frame, err := p.Attestation(sig)
	if err != nil {
		t.Fatal(err)
	}
	if string(frame[:4]) != "PFA1" || int(binary.BigEndian.Uint32(frame[4:8])) != n || len(frame) != 8+n+64 {
		t.Fatal("bad PFA1 frame")
	}
	if !bytes.Equal(frame[8:8+n], p.HeaderBytes()) || !ed25519.Verify(key.Public().(ed25519.PublicKey), input, frame[8+n:]) {
		t.Fatal("frame/transcript signature mismatch")
	}
	mutated := bytes.Clone(input)
	mutated[len(mutated)-1] ^= 1
	if ed25519.Verify(key.Public().(ed25519.PublicKey), mutated, frame[8+n:]) {
		t.Fatal("manifest mutation accepted")
	}
	if p.EntryID() != "000007-aaaaaaaaaaaa" {
		t.Fatal("wrong entry directory name")
	}
}

func TestPreparedBytesDoNotAliasCallerBuffers(t *testing.T) {
	manifest, receipt := []byte("manifest"), []byte("receipt")
	p, err := Prepare(testClaims(), manifest, receipt)
	if err != nil {
		t.Fatal(err)
	}
	wantHeader, wantInput := p.HeaderBytes(), p.SigningBytes()
	manifest[0], receipt[0] = 'X', 'Y'
	h, input := p.HeaderBytes(), p.SigningBytes()
	h[0], input[0] = 'X', 'Y'
	sig := bytes.Repeat([]byte{1}, 64)
	frame, err := p.Attestation(sig)
	if err != nil {
		t.Fatal(err)
	}
	sig[0], frame[8] = 2, 'X'
	if !bytes.Equal(p.HeaderBytes(), wantHeader) || !bytes.Equal(p.SigningBytes(), wantInput) {
		t.Fatal("caller mutated prepared bytes")
	}
	other, _ := p.Attestation(bytes.Repeat([]byte{1}, 64))
	if other[8] == 'X' {
		t.Fatal("frame aliases header")
	}
}

func TestInvalidClaimsRefuseBeforeConstruction(t *testing.T) {
	cases := map[string]func(*Claims){
		"key-empty": func(c *Claims) { c.KeyID = "" }, "key-path": func(c *Claims) { c.KeyID = "a/b" },
		"key-upper": func(c *Claims) { c.KeyID = "Key" }, "key-length": func(c *Claims) { c.KeyID = strings.Repeat("a", 65) },
		"receipt-url": func(c *Claims) { c.ReceiptRef = "https://x" }, "receipt-length": func(c *Claims) { c.ReceiptRef = strings.Repeat("a", 129) },
		"target-nonascii": func(c *Claims) { c.TargetProfile = "aé" }, "target-percent": func(c *Claims) { c.TargetProfile = "a%20b" },
		"head-sha256": func(c *Claims) { c.Head = strings.Repeat("a", 64) }, "head-upper": func(c *Claims) { c.Head = strings.Repeat("A", 40) },
		"tree-short": func(c *Claims) { c.Tree = "b" }, "digest-short": func(c *Claims) { c.TargetDigest = "c" },
		"sequence-zero": func(c *Claims) { c.Sequence = 0 }, "sequence-large": func(c *Claims) { c.Sequence = 1000000 },
		"profile-zero": func(c *Claims) { c.ProfileGeneration = 0 }, "policy-zero": func(c *Claims) { c.PolicyGeneration = 0 },
		"trust-zero": func(c *Claims) { c.TrustGeneration = 0 }, "revocation-zero": func(c *Claims) { c.RevocationGeneration = 0 },
		"profile-large": func(c *Claims) { c.ProfileGeneration = MaxGeneration + 1 }, "policy-large": func(c *Claims) { c.PolicyGeneration = MaxGeneration + 1 },
		"trust-large": func(c *Claims) { c.TrustGeneration = MaxGeneration + 1 }, "revocation-large": func(c *Claims) { c.RevocationGeneration = MaxGeneration + 1 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := testClaims()
			change(&c)
			p, err := Prepare(c, []byte("m"), []byte("r"))
			if err == nil || len(p.HeaderBytes()) != 0 || len(p.SigningBytes()) != 0 {
				t.Fatal("constructed invalid claims")
			}
		})
	}
}

func TestStrictCalendarAndExpiry(t *testing.T) {
	for _, value := range []string{"2026-11-04T00:00:00.1Z", "2026-11-04T00:00:00+00:00", "2026-11-04 00:00:00Z", "2026-11-04T00:00:60Z", "2026-02-29T00:00:00Z", "0000-01-01T00:00:00Z", "２０２６-11-04T00:00:00Z"} {
		for _, expiry := range []bool{false, true} {
			c := testClaims()
			if expiry {
				c.ExpiresAt = value
			} else {
				c.IssuedAt = value
			}
			if _, err := Prepare(c, []byte("m"), []byte("r")); err == nil {
				t.Fatalf("accepted %q expiry=%v", value, expiry)
			}
		}
	}
	for _, end := range []string{"2026-11-04T00:00:00Z", "2026-11-03T23:59:59Z"} {
		c := testClaims()
		c.ExpiresAt = end
		if _, err := Prepare(c, []byte("m"), []byte("r")); err == nil {
			t.Fatal("non-increasing expiry accepted")
		}
	}
	c := testClaims()
	c.IssuedAt = "2024-02-29T00:00:00Z"
	c.ExpiresAt = "2024-03-01T00:00:00Z"
	if _, err := Prepare(c, []byte("m"), []byte("r")); err != nil {
		t.Fatal(err)
	}
}

func TestByteAndIntegerBounds(t *testing.T) {
	for _, item := range []struct {
		m, r int
		ok   bool
	}{{0, 1, false}, {1, 0, false}, {MaxManifestBytes + 1, 1, false}, {1, MaxReceiptBytes + 1, false}, {MaxManifestBytes, MaxReceiptBytes, true}} {
		c := testClaims()
		c.Sequence = 999999
		c.ProfileGeneration = MaxGeneration
		c.PolicyGeneration = MaxGeneration
		c.TrustGeneration = MaxGeneration
		c.RevocationGeneration = MaxGeneration
		p, err := Prepare(c, bytes.Repeat([]byte{'m'}, item.m), bytes.Repeat([]byte{'r'}, item.r))
		if (err == nil) != item.ok {
			t.Fatalf("bounds %v: %v", item, err)
		}
		if item.ok {
			if !strings.HasPrefix(p.EntryID(), "999999-") {
				t.Fatal("entry sequence bound")
			}
			var h map[string]json.RawMessage
			_ = json.Unmarshal(p.HeaderBytes(), &h)
			if string(h["trust_generation"]) != "9007199254740991" {
				t.Fatal("integer precision lost")
			}
		}
	}
	var zero Prepared
	if _, err := zero.Attestation(make([]byte, 64)); err == nil {
		t.Fatal("zero prepared value accepted")
	}
	p, err := Prepare(testClaims(), []byte("m"), []byte("r"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 63, 65} {
		if _, err := p.Attestation(make([]byte, n)); err == nil {
			t.Fatalf("accepted %d signature bytes", n)
		}
	}
}
