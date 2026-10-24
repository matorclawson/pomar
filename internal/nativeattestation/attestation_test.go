package nativeattestation

// sow: pomar-SOW-90. Synthetic keys, identities, raw bytes and private observers
// only. No host key loader, executor, signer adoption or live authority is used.
import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/result"
)

func fixture(t *testing.T) (Policy, Original, observation, time.Time, ed25519.PrivateKey) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	policy := Policy{
		Schema: PolicySchema, ID: "profrod-native-release", Generation: "fixture-1",
		ValidFrom: now.Add(-time.Minute), ValidUntil: now.Add(2 * time.Minute),
		Source: Source{Repository: ProfRodRepository, Ref: "refs/heads/main", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Tree: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ManifestSHA256: digest([]byte("source")), Clean: true},
		Recipe: ProfRodRecipe, Argv: []string{"/synthetic/tools/make", "--no-print-directory", "hetzner-ci"},
		EnvironmentSHA256: digest([]byte("closed environment")), ToolClosureSHA256: digest([]byte("complete tool closure")),
		Tools:    []Tool{{Name: "make", Path: "/synthetic/tools/make", SHA256: digest([]byte("make"))}},
		Platform: Platform{OS: "darwin", Version: "fixture-version", Build: "fixture-build", Architecture: "arm64"},
		Producer: Producer{Principal: "fixture-protected-producer", UID: 410, Observer: "fixture-native-observer", ObserverVersion: "fixture-1", SigningKeyID: result.KeyID(key.Public().(ed25519.PublicKey)), SigningPurpose: Schema},
		Caller:   "fixture-profrod", CallerUID: 503,
		Inputs:  []File{{Name: "opportunity-sources.json", Bytes: 1, SHA256: digest([]byte("a"))}, {Name: "public-config.json", Bytes: 1, SHA256: digest([]byte("b"))}},
		Outputs: []Output{{Name: "release.json.gz", MaxBytes: 2048}}, MaxLogBytes: 1024, MaxArtifactBytes: 2048, MaxReturnBytes: 128 * 1024,
	}
	argv, err := result.Canonical(policy.Argv)
	if err != nil {
		t.Fatal(err)
	}
	original := Original{ID: "fixture-original", Incarnation: "fixture-incarnation", AdmissionSHA256: digest([]byte("admission")), JournalSHA256: digest([]byte("journal")), CommandSHA256: digest(argv), Caller: policy.Caller, CallerUID: policy.CallerUID, CallerPID: 1234, CallerBirth: "fixture-caller-birth", BootID: digest([]byte("boot")), Clock: ContinuousClock, OriginTick: 100, DeadlineTick: 1000, Origin: now.Add(-10 * time.Second), Deadline: now.Add(time.Minute)}
	policyID, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, artifact := []byte("complete stdout"), []byte{}, []byte("inert release bytes")
	proof := Proof{Schema: Schema, PolicySHA256: policyID, Original: original, Source: policy.Source, Recipe: policy.Recipe, Argv: append([]string(nil), policy.Argv...), EnvironmentSHA256: policy.EnvironmentSHA256, ToolClosureSHA256: policy.ToolClosureSHA256, Tools: append([]Tool(nil), policy.Tools...), Platform: policy.Platform, Producer: policy.Producer, Inputs: append([]File(nil), policy.Inputs...), Stdout: File{Name: "stdout", Bytes: int64(len(stdout)), SHA256: digest(stdout)}, Stderr: File{Name: "stderr", Bytes: 0, SHA256: digest(stderr)}, Artifacts: []File{{Name: "release.json.gz", Bytes: int64(len(artifact)), SHA256: digest(artifact)}}, State: "exited", ExitCode: 0,
		Lifecycle: Lifecycle{PID: 4321, BirthSeconds: 123, BirthMicros: 456, ExecutableSHA256: policy.Tools[0].SHA256, Start: now.Add(-9 * time.Second), NativeEnd: now.Add(-8 * time.Second), Wait: now.Add(-7 * time.Second), Cleanup: now.Add(-6 * time.Second), Frozen: now.Add(-5 * time.Second), StartTick: 200, EndTick: 300, WaitTick: 400, CleanupTick: 500, FrozenTick: 600, Waited: true, StreamsComplete: true, ArtifactsComplete: true, CleanupComplete: true, JournalDurable: true, CleanupSHA256: digest([]byte("positive cleanup"))}}
	if err := policy.Check(proof, original, now); err != nil {
		t.Fatal(err)
	}
	return policy, original, observation{proof: proof, stdout: stdout, stderr: stderr, artifacts: map[string][]byte{"release.json.gz": artifact}}, now, key
}

func cloneProof(t *testing.T, p Proof) Proof {
	t.Helper()
	b, err := Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func signature(key ed25519.PrivateKey, doc []byte) []byte {
	return ed25519.Sign(key, append([]byte(result.NativeSignatureContext), doc...))
}

func TestVerifyRequiresNativeDomainPinnedPurposeAndExactFrozenBytes(t *testing.T) {
	policy, original, observed, now, key := fixture(t)
	doc, err := Canonical(observed.proof)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	got, err := Verify(pub, doc, signature(key, doc), policy, original, now)
	if err != nil || got.Original.ID != original.ID {
		t.Fatal("legitimate synthetic proof", err)
	}
	for name, sig := range map[string][]byte{
		"legacy-raw": ed25519.Sign(key, doc),
		"closure":    ed25519.Sign(key, append([]byte("pomar.closure/v1\x00"), doc...)),
		"truncated":  signature(key, doc)[:20],
		"empty":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(pub, doc, sig, policy, original, now); !errors.Is(err, ErrInvalid) {
				t.Fatal("foreign signature/domain accepted", err)
			}
		})
	}
	changed := bytes.Clone(doc)
	changed[len(changed)/2] ^= 1
	if _, err := Verify(pub, changed, signature(key, doc), policy, original, now); err == nil {
		t.Fatal("changed signed bytes accepted")
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	if _, err := Verify(other.Public().(ed25519.PublicKey), doc, signature(other, doc), policy, original, now); err == nil {
		t.Fatal("unadopted key rotation accepted")
	}
}

func TestDecodeRefusesAmbiguousOrOpenWire(t *testing.T) {
	_, _, observed, _, _ := fixture(t)
	doc, err := Canonical(observed.proof)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"duplicate-field":    append([]byte(`{"schema":"forged",`), doc[1:]...),
		"unknown-field":      append([]byte(`{"authority_override":true,`), doc[1:]...),
		"second-document":    append(bytes.Clone(doc), []byte(`{}`)...),
		"noncanonical-space": append(bytes.Clone(doc), ' '),
		"partial":            doc[:len(doc)/2],
		"oversize":           bytes.Repeat([]byte{' '}, MaxDocumentBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(bad); !errors.Is(err, ErrInvalid) {
				t.Fatal("ambiguous/open document accepted", err)
			}
		})
	}
}

func TestSignedChangedObservationCannotBorrowExpectedPolicyOrOriginal(t *testing.T) {
	policy, original, observed, now, key := fixture(t)
	changes := map[string]func(*Proof){
		"guest-schema":          func(p *Proof) { p.Schema = result.Schema },
		"policy":                func(p *Proof) { p.PolicySHA256 = digest([]byte("other")) },
		"original":              func(p *Proof) { p.Original.ID = "another-original" },
		"incarnation":           func(p *Proof) { p.Original.Incarnation += "-new" },
		"journal":               func(p *Proof) { p.Original.JournalSHA256 = digest([]byte("imported")) },
		"origin-reset":          func(p *Proof) { p.Original.Origin = p.Original.Origin.Add(time.Second) },
		"deadline-reset":        func(p *Proof) { p.Original.Deadline = p.Original.Deadline.Add(time.Second) },
		"boot":                  func(p *Proof) { p.Original.BootID = digest([]byte("another boot")) },
		"source":                func(p *Proof) { p.Source.Commit = "cccccccccccccccccccccccccccccccccccccccc" },
		"dirty-source":          func(p *Proof) { p.Source.Clean = false },
		"input":                 func(p *Proof) { p.Inputs[0].SHA256 = digest([]byte("changed")) },
		"command":               func(p *Proof) { p.Argv[2] = "other-target" },
		"tool":                  func(p *Proof) { p.Tools[0].SHA256 = digest([]byte("changed")) },
		"tool-closure":          func(p *Proof) { p.ToolClosureSHA256 = digest([]byte("changed")) },
		"environment":           func(p *Proof) { p.EnvironmentSHA256 = digest([]byte("ambient")) },
		"OS":                    func(p *Proof) { p.Platform.OS = "linux" },
		"principal":             func(p *Proof) { p.Producer.Principal = "actor" },
		"purpose":               func(p *Proof) { p.Producer.SigningPurpose = result.Schema },
		"native-executable":     func(p *Proof) { p.Lifecycle.ExecutableSHA256 = digest([]byte("wrong executable")) },
		"no-wait":               func(p *Proof) { p.Lifecycle.Waited = false },
		"partial-log":           func(p *Proof) { p.Lifecycle.StreamsComplete = false },
		"partial-output":        func(p *Proof) { p.Lifecycle.ArtifactsComplete = false },
		"unknown-cleanup":       func(p *Proof) { p.Lifecycle.CleanupComplete = false },
		"missing-journal-flush": func(p *Proof) { p.Lifecycle.JournalDurable = false },
		"time-order":            func(p *Proof) { p.Lifecycle.Wait = p.Lifecycle.NativeEnd.Add(-time.Second) },
		"continuous-clock":      func(p *Proof) { p.Lifecycle.CleanupTick = p.Original.DeadlineTick },
		"exit-failure":          func(p *Proof) { p.ExitCode = 1 },
		"renamed-output":        func(p *Proof) { p.Artifacts[0].Name = "other.gz" },
		"truncated-identity":    func(p *Proof) { p.Artifacts[0].SHA256 = "" },
		"over-limit":            func(p *Proof) { p.Stdout.Bytes = policy.MaxLogBytes + 1 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			proof := cloneProof(t, observed.proof)
			change(&proof)
			doc, err := Canonical(proof)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(key.Public().(ed25519.PublicKey), doc, signature(key, doc), policy, original, now); !errors.Is(err, ErrInvalid) {
				t.Fatal("changed signed observation accepted", err)
			}
		})
	}
	if _, err := Verify(key.Public().(ed25519.PublicKey), mustCanonical(t, observed.proof), signature(key, mustCanonical(t, observed.proof)), policy, original, original.Deadline); err == nil {
		t.Fatal("expired original accepted")
	}
}

func mustCanonical(t *testing.T, p Proof) []byte {
	t.Helper()
	b, err := Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func clonePolicy(t *testing.T, p Policy) Policy {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var q Policy
	if err := json.Unmarshal(b, &q); err != nil {
		t.Fatal(err)
	}
	return q
}
