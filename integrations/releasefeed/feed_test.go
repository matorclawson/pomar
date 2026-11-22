package releasefeed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type sourceFunc func(context.Context, uint64) (Entry, error)

func (f sourceFunc) Lookup(ctx context.Context, sequence uint64) (Entry, error) {
	return f(ctx, sequence)
}

func TestReadBindsProducerSequenceAndOriginalManifest(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	trust := Trust{Producer: "example/releases", PublicKey: key.Public().(ed25519.PublicKey)}
	entry := Entry{Producer: trust.Producer, Sequence: 3, IssuedAt: 10, ExpiresAt: 20, Manifest: []byte("{\"version\":1}\n")}
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
		"issued at": func(e *Entry) { e.IssuedAt++ },
		"expiry":    func(e *Entry) { e.ExpiresAt++ },
		"no expiry": func(e *Entry) { e.ExpiresAt = 0 },
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

func TestActivationRequiresFreshStrictlyIncreasingDurableSequence(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	trust := Trust{Producer: "example/releases", PublicKey: key.Public().(ed25519.PublicKey)}
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "admission")
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	source := func(sequence uint64, issued, expires time.Time) Source {
		entry := Entry{
			Producer: trust.Producer, Sequence: sequence,
			IssuedAt: issued.Unix(), ExpiresAt: expires.Unix(), Manifest: []byte("example"),
		}
		raw, err := SigningBytes(entry)
		if err != nil {
			t.Fatal(err)
		}
		entry.Signature = ed25519.Sign(key, raw)
		return sourceFunc(func(context.Context, uint64) (Entry, error) { return entry, nil })
	}
	var called int
	activationFailed := errors.New("activation outcome requires owner reconciliation")
	higher := source(4, now.Add(-time.Hour), now.Add(time.Hour))
	activate := func(_ context.Context, entry Entry) error {
		called++
		root, err := os.OpenRoot(dir)
		if err != nil {
			return err
		}
		defer root.Close()
		seq, err := readSequence(root, entry.Producer)
		if err != nil || seq != entry.Sequence {
			t.Fatalf("sequence %d not persisted before activation: %d, %v", entry.Sequence, seq, err)
		}
		if err := Activate(ctx, higher, trust, 4, dir, clock, func(context.Context, Entry) error {
			t.Fatal("concurrent activation entered before its predecessor finished")
			return nil
		}); err == nil {
			t.Fatal("concurrent activation did not report its unavailable lock")
		}
		return activationFailed
	}
	first := source(3, now.Add(-time.Hour), now.Add(time.Hour))
	if err := Activate(ctx, first, trust, 3, dir, clock, activate); err == nil || called != 0 {
		t.Fatalf("activated without initialized state: %v", err)
	}
	if err := InitializeAdmission(dir, trust.Producer); err != nil {
		t.Fatal(err)
	}
	expired := source(8, now.Add(-2*time.Hour), now)
	if _, err := Read(ctx, expired, trust, 8); err != nil {
		t.Fatalf("historical inspection refused: %v", err)
	}
	future := source(9, now.Add(time.Hour), now.Add(2*time.Hour))
	for sequence, src := range map[uint64]Source{8: expired, 9: future} {
		if err := Activate(ctx, src, trust, sequence, dir, clock, activate); err == nil || called != 0 {
			t.Fatalf("activated outside validity interval at sequence %d: %v", sequence, err)
		}
	}
	if err := Activate(ctx, first, trust, 3, dir, clock, activate); !errors.Is(err, activationFailed) || called != 1 {
		t.Fatalf("fresh admission did not invoke activation: %v", err)
	}
	older := source(2, now.Add(-time.Hour), now.Add(time.Hour))
	for sequence, src := range map[uint64]Source{2: older, 3: first} {
		if err := Activate(ctx, src, trust, sequence, dir, clock, activate); err == nil || called != 1 {
			t.Fatalf("reactivated sequence %d after reopening state: %v", sequence, err)
		}
	}
	if err := os.Remove(filepath.Join(dir, admissionFile)); err != nil {
		t.Fatal(err)
	}
	if err := InitializeAdmission(dir, trust.Producer); err == nil {
		t.Fatal("initialized over an existing admission directory with lost state")
	}
	if err := Activate(ctx, first, trust, 3, dir, clock, activate); err == nil || called != 1 {
		t.Fatalf("reactivated after loss of durable state: %v", err)
	}
}
