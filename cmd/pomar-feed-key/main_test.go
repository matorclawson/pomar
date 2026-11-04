package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig(t *testing.T) config {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	// Public deterministic TEST-ONLY bytes. Never an operational custodian key.
	return config{home, host, "test-feed-key", os.Geteuid(), os.Getegid(), bytes.NewReader(bytes.Repeat([]byte{9}, 32))}
}

func TestPublicCryptoAndWrongRoleHaveNoCustodyEffects(t *testing.T) {
	c := testConfig(t)
	c.home = filepath.Join(c.home, "absent")
	c.uid = 530
	c.gid = 530
	var out bytes.Buffer
	if err := run(c, "self-test-public", &out); err != nil || !strings.Contains(out.String(), "PUBLIC_SELF_TEST_PASS") {
		t.Fatal(err)
	}
	if os.Geteuid() != 530 {
		if err := run(c, "generate", &out); err == nil {
			t.Fatal("wrong role accepted")
		}
	}
	if _, err := os.Lstat(c.home); !os.IsNotExist(err) {
		t.Fatal("role refusal created custody path")
	}
	if err := run(c, "sign-arbitrary", &out); err == nil {
		t.Fatal("arbitrary signer operation accepted")
	}
}

func TestExclusiveGenerationPersistsPublicBindingAndNeverPrintsSeed(t *testing.T) {
	c := testConfig(t)
	var out bytes.Buffer
	if err := run(c, "generate", &out); err != nil {
		t.Fatal(err)
	}
	var got publicRecord
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.KeyID != c.keyID || got.Algorithm != "Ed25519" || got.Status != "PUBLIC_NOT_YET_TRUST_ADOPTED" {
		t.Fatal("wrong public record")
	}
	seed, err := os.ReadFile(filepath.Join(c.home, "ed25519.seed"))
	if err != nil || !bytes.Equal(seed, bytes.Repeat([]byte{9}, 32)) {
		t.Fatal("test seed not persisted")
	}
	s, err := os.Stat(filepath.Join(c.home, "ed25519.seed"))
	if err != nil || s.Mode().Perm() != 0600 || s.Size() != 32 {
		t.Fatal("bad persisted metadata")
	}
	if bytes.Contains(out.Bytes(), seed) || strings.Contains(out.String(), "seed") {
		t.Fatal("private seed in output")
	}
	before := out.String()
	out.Reset()
	if err := run(c, "public", &out); err != nil || out.String() != before {
		t.Fatal("public binding not repeatable", err)
	}
	out.Reset()
	if err := run(c, "generate", &out); err == nil || out.Len() != 0 {
		t.Fatal("existing generation was replayed")
	}
	after, _ := os.ReadFile(filepath.Join(c.home, "ed25519.seed"))
	if !bytes.Equal(seed, after) {
		t.Fatal("existing seed changed")
	}
}

func TestEntropyFailureRetainsIntentAndCannotRetry(t *testing.T) {
	c := testConfig(t)
	c.entropy = bytes.NewReader(nil)
	var out bytes.Buffer
	if err := run(c, "generate", &out); err == nil || out.Len() != 0 {
		t.Fatal("false success")
	}
	if _, err := os.Stat(filepath.Join(c.home, "generation.intent.json")); err != nil {
		t.Fatal("intent lost")
	}
	if _, err := os.Stat(filepath.Join(c.home, "ed25519.seed")); !os.IsNotExist(err) {
		t.Fatal("failed entropy persisted a seed")
	}
	c.entropy = bytes.NewReader(bytes.Repeat([]byte{9}, 32))
	if err := run(c, "generate", &out); err == nil {
		t.Fatal("uncertain intent replayed")
	}
}

func TestMissingDriftAndRedirectRefusePublicReadback(t *testing.T) {
	for _, kind := range []string{"missing-record", "changed-seed", "changed-public", "seed-link", "home-mode"} {
		t.Run(kind, func(t *testing.T) {
			c := testConfig(t)
			var out bytes.Buffer
			if err := run(c, "generate", &out); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			switch kind {
			case "missing-record":
				if err := os.Remove(filepath.Join(c.home, "public-key.json")); err != nil {
					t.Fatal(err)
				}
			case "changed-seed":
				if err := os.WriteFile(filepath.Join(c.home, "ed25519.seed"), bytes.Repeat([]byte{8}, 32), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-public":
				if err := os.WriteFile(filepath.Join(c.home, "public-key.json"), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "seed-link":
				seed := filepath.Join(c.home, "ed25519.seed")
				if err := os.Rename(seed, seed+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("ed25519.seed.old", seed); err != nil {
					t.Fatal(err)
				}
			case "home-mode":
				if err := os.Chmod(c.home, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := run(c, "public", &out); err == nil || out.Len() != 0 {
				t.Fatal("drift accepted")
			}
		})
	}
}

func TestRehearsalHasSeparateCustodyAndIdentity(t *testing.T) {
	c := testConfig(t)
	var prod, rehearsal bytes.Buffer
	if e := run(c, "generate", &prod); e != nil {
		t.Fatal(e)
	}
	// Separate entropy fixture: the production key must not be reused.
	c.entropy = bytes.NewReader(bytes.Repeat([]byte{7}, 32))
	if e := run(c, "generate-rehearsal", &rehearsal); e != nil {
		t.Fatal(e)
	}
	var p, r publicRecord
	if json.Unmarshal(prod.Bytes(), &p) != nil || json.Unmarshal(rehearsal.Bytes(), &r) != nil || r.KeyID != "pomar-feed-rehearsal-a-202611" || r.PublicKey == p.PublicKey {
		t.Fatal("rehearsal shares production identity")
	}
	rehearsal.Reset()
	if e := run(c, "public-rehearsal", &rehearsal); e != nil {
		t.Fatal(e)
	}
	if e := run(c, "generate-rehearsal", &rehearsal); e == nil {
		t.Fatal("rehearsal replay allowed")
	}
	var reread bytes.Buffer
	if e := run(c, "public", &reread); e != nil || !bytes.Equal(prod.Bytes(), reread.Bytes()) {
		t.Fatal("production custody changed")
	}
}
