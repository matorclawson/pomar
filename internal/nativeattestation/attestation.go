// Package nativeattestation defines the closed native proof contract. It does
// not install an observer, admit work, load keys or turn imported JSON into an
// observation. A signature is useful only with independently pinned policy.
// sow: pomar-SOW-90
package nativeattestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/result"
)

const Schema = result.NativeSchema
const MaxDocumentBytes = result.NativeMaxDocumentBytes

var ErrInvalid = errors.New("native attestation: invalid evidence")

// Original identifies the already admitted execution, not a new run request.
// Its journal and caller bindings must be authenticated by the protected owner.
type Original struct {
	ID              string    `json:"id"`
	Incarnation     string    `json:"incarnation"`
	AdmissionSHA256 string    `json:"admission_sha256"`
	JournalSHA256   string    `json:"journal_sha256"`
	CommandSHA256   string    `json:"command_sha256"`
	Caller          string    `json:"caller"`
	CallerUID       int       `json:"caller_uid"`
	CallerPID       int       `json:"caller_pid"`
	CallerBirth     string    `json:"caller_birth"`
	BootID          string    `json:"boot_id"`
	Clock           string    `json:"clock"`
	OriginTick      uint64    `json:"origin_tick"`
	DeadlineTick    uint64    `json:"deadline_tick"`
	Origin          time.Time `json:"origin"`
	Deadline        time.Time `json:"deadline"`
}

type File struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type Source struct {
	Repository     string `json:"repository"`
	Ref            string `json:"ref"`
	Commit         string `json:"commit"`
	Tree           string `json:"tree"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Clean          bool   `json:"clean"`
}

type Tool struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Platform struct {
	OS           string `json:"os"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	Architecture string `json:"architecture"`
}

type Producer struct {
	Principal       string `json:"principal"`
	UID             int    `json:"uid"`
	Observer        string `json:"observer"`
	ObserverVersion string `json:"observer_version"`
	SigningKeyID    string `json:"signing_key_id"`
	SigningPurpose  string `json:"signing_purpose"`
}

// Lifecycle carries positive owner observations. These fields are claims until
// authenticated by the real observer and independently verified by the consumer.
type Lifecycle struct {
	PID               int       `json:"pid"`
	BirthSeconds      uint64    `json:"birth_seconds"`
	BirthMicros       uint32    `json:"birth_microseconds"`
	ExecutableSHA256  string    `json:"executable_sha256"`
	Start             time.Time `json:"start"`
	NativeEnd         time.Time `json:"native_end"`
	Wait              time.Time `json:"wait"`
	Cleanup           time.Time `json:"cleanup"`
	Frozen            time.Time `json:"frozen"`
	StartTick         uint64    `json:"start_tick"`
	EndTick           uint64    `json:"end_tick"`
	WaitTick          uint64    `json:"wait_tick"`
	CleanupTick       uint64    `json:"cleanup_tick"`
	FrozenTick        uint64    `json:"frozen_tick"`
	Waited            bool      `json:"waited"`
	StreamsComplete   bool      `json:"streams_complete"`
	ArtifactsComplete bool      `json:"artifacts_complete"`
	CleanupComplete   bool      `json:"cleanup_complete"`
	CleanupSHA256     string    `json:"cleanup_sha256"`
	JournalDurable    bool      `json:"journal_durable"`
}

// Proof is a successful, newly observed native execution. Failed, incomplete or
// uncertain runs remain with the original owner; this wire cannot claim success
// for them. No guest image/kernel proof is implied by this distinct schema.
type Proof struct {
	Schema            string    `json:"schema"`
	PolicySHA256      string    `json:"policy_sha256"`
	Original          Original  `json:"original"`
	Source            Source    `json:"source"`
	Recipe            string    `json:"recipe"`
	Argv              []string  `json:"argv"`
	EnvironmentSHA256 string    `json:"environment_sha256"`
	ToolClosureSHA256 string    `json:"tool_closure_sha256"`
	Tools             []Tool    `json:"tools"`
	Platform          Platform  `json:"platform"`
	Producer          Producer  `json:"producer"`
	Inputs            []File    `json:"inputs"`
	Stdout            File      `json:"stdout"`
	Stderr            File      `json:"stderr"`
	Artifacts         []File    `json:"artifacts"`
	Lifecycle         Lifecycle `json:"lifecycle"`
	State             string    `json:"state"`
	ExitCode          int       `json:"exit_code"`
}

// Canonical encodes a proof, without granting it observation authority. The
// collector applies policy and raw-byte checks before freezing these bytes.
func Canonical(p Proof) ([]byte, error) {
	b, err := result.Canonical(p)
	if err != nil || len(b) > MaxDocumentBytes {
		return nil, fmt.Errorf("%w: document encoding or bound", ErrInvalid)
	}
	return b, nil
}

// Decode refuses unknown fields, duplicates, alternate encodings and suffixes.
// Requiring the exact canonical re-encoding also prevents distinct wire bytes
// from hiding behind the same decoded original/policy binding.
func Decode(doc []byte) (Proof, error) {
	var p Proof
	if len(doc) == 0 || len(doc) > MaxDocumentBytes {
		return p, fmt.Errorf("%w: document bound", ErrInvalid)
	}
	d := json.NewDecoder(bytes.NewReader(doc))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return Proof{}, fmt.Errorf("%w: document shape", ErrInvalid)
	}
	var suffix any
	if err := d.Decode(&suffix); err != io.EOF {
		return Proof{}, fmt.Errorf("%w: trailing document", ErrInvalid)
	}
	b, err := Canonical(p)
	if err != nil || !bytes.Equal(b, doc) {
		return Proof{}, fmt.Errorf("%w: noncanonical document", ErrInvalid)
	}
	return p, nil
}

// Verify requires an independently obtained policy, public key and original.
// It verifies original frozen bytes, never a reserialized substitute.
func Verify(pub ed25519.PublicKey, doc, signature []byte, policy Policy, original Original, now time.Time) (Proof, error) {
	if len(pub) != ed25519.PublicKeySize || result.KeyID(pub) != policy.Producer.SigningKeyID || !result.VerifyNative(pub, doc, signature) {
		return Proof{}, fmt.Errorf("%w: native signing identity/domain", ErrInvalid)
	}
	p, err := Decode(doc)
	if err != nil {
		return Proof{}, err
	}
	if err := policy.Check(p, original, now); err != nil {
		return Proof{}, err
	}
	return p, nil
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func same(a, b any) bool {
	x, err := result.Canonical(a)
	if err != nil {
		return false
	}
	y, err := result.Canonical(b)
	return err == nil && bytes.Equal(x, y)
}
