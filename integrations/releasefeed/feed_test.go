package releasefeed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
)

type sourceFunc func(context.Context, uint64) (Entry, error)

func (f sourceFunc) Lookup(ctx context.Context, sequence uint64) (Entry, error) {
	return f(ctx, sequence)
}

func TestReadBindsProducerSequenceAndOriginalManifest(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	trust := Trust{Producer: "example/releases", PublicKey: key.Public().(ed25519.PublicKey)}
	entry := Entry{Producer: trust.Producer, Sequence: 3, Manifest: []byte("{\"version\":1}\n")}
	raw, err := SigningBytes(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.Signature = ed25519.Sign(key, raw)
	source := sourceFunc(func(ctx context.Context, seq uint64) (Entry, error) {
		if _, ok := ctx.Deadline(); !ok || seq != 3 {
			t.Fatal("lookup is not bounded to the requested sequence")
		}
		return entry, nil
	})
	got, err := Read(context.Background(), source, trust, 3)
	if err != nil || !bytes.Equal(got.Manifest, entry.Manifest) {
		t.Fatalf("valid entry rejected: %v", err)
	}
	got.Manifest[0] ^= 1
	if bytes.Equal(got.Manifest, entry.Manifest) {
		t.Fatal("verified entry aliases the source")
	}
	for name, mutate := range map[string]func(*Entry){
		"producer":  func(e *Entry) { e.Producer = "other" },
		"sequence":  func(e *Entry) { e.Sequence++ },
		"manifest":  func(e *Entry) { e.Manifest = append(bytes.Clone(e.Manifest), ' ') },
		"oversized": func(e *Entry) { e.Manifest = []byte(strings.Repeat("a", MaxManifestBytes+1)) },
		"signature": func(e *Entry) { e.Signature = make([]byte, ed25519.SignatureSize) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := entry
			mutate(&bad)
			source := sourceFunc(func(context.Context, uint64) (Entry, error) { return bad, nil })
			if _, err := Read(context.Background(), source, trust, 3); err == nil {
				t.Fatal("accepted altered signed entry")
			}
		})
	}
}
