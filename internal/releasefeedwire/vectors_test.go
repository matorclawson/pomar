package releasefeedwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Published consumer TEST keys only. Reproduce all three complete accepted
// signatures byte for byte using the producer's actual transcript constructor.
func TestConsumerPublishedVectorsExactSignatures(t *testing.T) {
	seed := sha256.Sum256([]byte("zeoconnect test-only pomar feed seed: test-feed-a"))
	key := ed25519.NewKeyFromSeed(seed[:])
	if got := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)); got != "tqTRYwh4mYaTSMu44P5CRr8KTWYqe4NwBwi5P6xV2Jw=" {
		t.Fatal("consumer public test key mismatch")
	}
	for _, name := range []string{"accepted-release-1", "accepted-release-2-one-wheel", "accepted-release-2-four-wheels"} {
		t.Run(name, func(t *testing.T) {
			att, err := os.ReadFile(filepath.Join("testdata", name, "attestation.bin"))
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := os.ReadFile(filepath.Join("testdata", name, "release.json"))
			if err != nil {
				t.Fatal(err)
			}
			n := int(binary.BigEndian.Uint32(att[4:8]))
			if string(att[:4]) != "PFA1" || len(att) != 8+n+64 {
				t.Fatal("invalid fixture frame")
			}
			raw := att[8 : 8+n]
			input := signatureInput(raw, manifest)
			sig := ed25519.Sign(key, input)
			if !bytes.Equal(sig, att[8+n:]) {
				t.Fatal("exact consumer signature not reproduced")
			}
			p := Prepared{header: raw, signingInput: input}
			got, err := p.Attestation(sig)
			if err != nil || !bytes.Equal(got, att) {
				t.Fatal("exact complete consumer attestation not reproduced")
			}
			for _, which := range []string{"header", "manifest", "signature"} {
				h := bytes.Clone(raw)
				m := bytes.Clone(manifest)
				s := bytes.Clone(sig)
				switch which {
				case "header":
					h[0] ^= 1
				case "manifest":
					m[0] ^= 1
				case "signature":
					s[0] ^= 1
				}
				if ed25519.Verify(key.Public().(ed25519.PublicKey), signatureInput(h, m), s) {
					t.Fatal("mutation accepted", which)
				}
			}
		})
	}
}
