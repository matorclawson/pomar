package releaseexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const EnvelopeSchema = "pomar.private-release-envelope/v1"

type Member struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	Mode string `json:"mode"`
	Bytes int64 `json:"bytes"`
	SHA256 string `json:"sha256"`
	Target string `json:"target"`
}

type Artifact struct {
	SHA256 string `json:"sha256"`
	Bytes int64 `json:"bytes"`
}

// Claims come from the owning canonical-payload verifier, not JSON claims that
// have merely been hashed. The shared component owns their canonical encoding.
type Claims struct {
	Repository string `json:"repository"`
	Commit string `json:"commit"`
	Tree string `json:"tree"`
	Version string `json:"version"`
	Tag string `json:"tag"`
	TagObject string `json:"tag_object"`
	NotesSHA256 string `json:"notes_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	ComponentSHA256 string `json:"component_sha256"`
	MainProofSHA256 string `json:"main_proof_sha256"`
	SharedEventSHA256 string `json:"shared_event_sha256"`
	BuildProfileSHA256 string `json:"build_profile_sha256"`
	ToolchainSHA256 string `json:"toolchain_sha256"`
	LockedInputsSHA256 string `json:"locked_inputs_sha256"`
	Platform string `json:"platform"`
	Artifact Artifact `json:"artifact"`
	Inventory []Member `json:"inventory"`
	ValidUntil int64 `json:"valid_until"`
}

type Envelope struct {
	Schema string `json:"schema"`
	Claims Claims `json:"claims"`
	SharedEvent []byte `json:"shared_event"`
	CanonicalPayload []byte `json:"canonical_payload"`
	PayloadSHA256 string `json:"payload_sha256"`
	SignatureReceipt Binding `json:"signature_receipt"`
	VerificationReceipt Binding `json:"verification_receipt"`
}

type EnvelopeVerifier interface {
	VerifyConfig(context.Context, Config, string) error
	VerifyMain(context.Context, Observation) error
	VerifyPayload(context.Context, []byte, Binding, Binding, Binding) (Claims, error)
	VerifySharedEvent(context.Context, []byte, Component, Claims) error
	VerifyContent(context.Context, Artifact, []Member) error
}

// VerifyEnvelope preserves the shared bytes and requires independent payload,
// main-provenance and final-content verifiers. There is no permissive default.
func VerifyEnvelope(ctx context.Context, data []byte, c Config, configPin string, o Observation, now time.Time, v EnvelopeVerifier) (Envelope, error) {
	var e Envelope
	if missing(v) {
		return e, ErrUnbound
	}
	if validateConfig(c) != nil || v.VerifyConfig(ctx, c, configPin) != nil {
		return e, ErrHeld
	}
	if strictDecode(data, &e, c.Limits.EnvelopeBytes) != nil || e.Schema != EnvelopeSchema ||
		!validBinding(e.SignatureReceipt) || !validBinding(e.VerificationReceipt) ||
		len(e.CanonicalPayload) == 0 || hashBytes(e.CanonicalPayload) != e.PayloadSHA256 ||
		len(e.SharedEvent) == 0 || !json.Valid(e.SharedEvent) ||
		hashBytes(e.SharedEvent) != e.Claims.SharedEventSHA256 {
		return Envelope{}, ErrInvalid
	}
	if v.VerifyMain(ctx, o) != nil {
		return Envelope{}, ErrHeld
	}
	signed, err := v.VerifyPayload(ctx, e.CanonicalPayload, e.SignatureReceipt, e.VerificationReceipt, c.Trust)
	if err != nil {
		return Envelope{}, ErrHeld
	}
	// Comparing own receipt data is not canonicalising or signing shared JSON.
	a, errA := json.Marshal(signed)
	b, errB := json.Marshal(e.Claims)
	if errA != nil || errB != nil || !bytes.Equal(a, b) ||
		e.Claims.Repository != c.Repository || e.Claims.Repository != o.Repository ||
		e.Claims.Commit != o.Commit || e.Claims.Tree != o.Tree ||
		!hexID(o.Commit, 40) || !hexID(o.Tree, 40) || len(o.Proof) == 0 ||
		e.Claims.MainProofSHA256 != hashBytes(o.Proof) ||
		e.Claims.ConfigSHA256 != configPin || !hexID(configPin, 64) ||
		e.Claims.ComponentSHA256 != c.Component.SHA256 ||
		e.Claims.BuildProfileSHA256 != c.Profiles.Build.SHA256 ||
		e.Claims.Platform != c.Platform || e.Claims.Version == "" ||
		!strings.HasPrefix(e.Claims.Tag, c.TagPrefix) || len(e.Claims.Tag) <= len(c.TagPrefix) ||
		!hexID(e.Claims.TagObject, 40) || !hexID(e.Claims.NotesSHA256, 64) ||
		!hexID(e.Claims.ToolchainSHA256, 64) || !hexID(e.Claims.LockedInputsSHA256, 64) ||
		now.IsZero() || e.Claims.ValidUntil <= now.Unix() || e.Claims.ValidUntil > c.ValidUntil ||
		!hexID(e.Claims.Artifact.SHA256, 64) || e.Claims.Artifact.Bytes <= 0 || e.Claims.Artifact.Bytes > c.Limits.ArtifactBytes ||
		validateInventory(e.Claims.Inventory, c.Limits.InventoryEntries, c.Limits.ExpandedBytes) != nil {
		return Envelope{}, ErrInvalid
	}
	if v.VerifySharedEvent(ctx, e.SharedEvent, c.Component, signed) != nil ||
		v.VerifyContent(ctx, e.Claims.Artifact, e.Claims.Inventory) != nil {
		return Envelope{}, ErrHeld
	}
	return e, nil
}

// EncodeEnvelope serialises only this outer receipt. It neither canonicalises
// the shared payload nor authenticates the receipt; VerifyEnvelope is required.
func EncodeEnvelope(e Envelope) ([]byte, error) {
	if e.Schema != EnvelopeSchema {
		return nil, ErrInvalid
	}
	b, err := json.Marshal(e)
	if err != nil || len(b) > MaxEnvelopeBytes {
		return nil, ErrInvalid
	}
	return b, nil
}

func safePath(s string) bool {
	if s == "" || s == "." || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "../") ||
		path.Clean(s) != s || strings.Contains(s, "\\") || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

func foldKey(s string) string {
	return strings.Map(func(r rune) rune {
		min := r
		for n := unicode.SimpleFold(r); n != r; n = unicode.SimpleFold(n) {
			if n < min {
				min = n
			}
		}
		return min
	}, s)
}

func validateInventory(items []Member, max int, expanded int64) error {
	if max <= 0 || expanded <= 0 || len(items) == 0 || len(items) > max {
		return ErrInvalid
	}
	seen := map[string]bool{}
	byPath := map[string]Member{}
	var total int64
	for _, m := range items {
		key := foldKey(m.Path)
		if !safePath(m.Path) || seen[key] {
			return ErrInvalid
		}
		seen[key] = true
		byPath[m.Path] = m
		switch m.Kind {
		case "file":
			if (m.Mode != "644" && m.Mode != "755") || m.Bytes < 0 || m.Bytes > expanded-total || !hexID(m.SHA256, 64) || m.Target != "" {
				return ErrInvalid
			}
			total += m.Bytes
		case "dir":
			if m.Mode != "755" || m.Bytes != 0 || m.SHA256 != "" || m.Target != "" {
				return ErrInvalid
			}
		case "symlink":
			resolved := path.Join(path.Dir(m.Path), m.Target)
			if m.Mode != "-" || m.Bytes != 0 || m.SHA256 != "" || m.Target == "" ||
				strings.HasPrefix(m.Target, "/") || strings.Contains(m.Target, "\\") || !safePath(resolved) {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	for _, m := range items {
		for parent := path.Dir(m.Path); parent != "."; parent = path.Dir(parent) {
			p, ok := byPath[parent]
			if !ok || p.Kind != "dir" {
				return ErrInvalid
			}
		}
	}
	return nil
}
