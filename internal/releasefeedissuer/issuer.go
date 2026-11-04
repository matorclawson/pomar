// Package releasefeedissuer constructs a closed, policy-bound feed issue.
// Its caller must authenticate the policy from the protected root-owned store,
// durably reserve the sequence BEFORE calling Build, and retain uncertainty.
// Neither an observation nor a signature alone establishes deployment eligibility.
package releasefeedissuer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedobserver"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedwire"
	"time"
)

const ProductionKeyID = "pomar-feed-a-202611"
const RehearsalKeyID = "pomar-feed-rehearsal-a-202611"

type Policy struct {
	Schema          string                 `json:"schema"`
	Purpose         string                 `json:"purpose"`
	Claims          releasefeedwire.Claims `json:"claims"`
	PublicKeySHA256 string                 `json:"public_key_sha256"`
	ReceiptSHA256   string                 `json:"receipt_sha256"`
	Files           map[string]string      `json:"files_sha256"`
	SuccessorDueAt  string                 `json:"successor_due_at"`
}
type Bundle struct {
	EntryID string
	Purpose string
	Files   map[string][]byte
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Build signs only the exact typed claims, observed receipt and pinned artifact
// snapshot of an already authenticated policy. It has no filesystem/policy
// discovery, CLI paths, raw-header override or arbitrary signature operation.
func Build(p Policy, receipt []byte, files map[string][]byte, key ed25519.PrivateKey, now time.Time) (Bundle, error) {
	fail := func(s string) (Bundle, error) { return Bundle{}, fmt.Errorf("issuance refused: %s", s) }
	if p.Schema != "pomar.feed-issuance-policy/v1" || len(key) != ed25519.PrivateKeySize {
		return fail("policy schema or key")
	}
	if (p.Purpose != "rehearsal" || p.Claims.KeyID != RehearsalKeyID) && (p.Purpose != "production" || p.Claims.KeyID != ProductionKeyID) {
		return fail("purpose/key isolation")
	}
	if hash(key.Public().(ed25519.PublicKey)) != p.PublicKeySHA256 || hash(receipt) != p.ReceiptSHA256 {
		return fail("public key or receipt pin")
	}
	if len(files) != len(p.Files) || len(files) < 3 || len(files) > 18 {
		return fail("file inventory")
	}
	for n, b := range files {
		expected, ok := p.Files[n]
		if !ok || hash(b) != expected {
			return fail("file pin")
		}
	}
	var r releasefeedobserver.Receipt
	if json.Unmarshal(receipt, &r) != nil || r.Schema != "pomar.release-artifact-observation/v1" || r.BuildQualification || r.DeploymentIndependentlyObserved || r.Head != p.Claims.Head || r.Tree != p.Claims.Tree || r.Sequence != p.Claims.Sequence {
		return fail("observation context")
	}
	observed, e := time.Parse("2006-01-02T15:04:05Z", r.ObservedAt)
	if e != nil || observed.After(now.Add(300*time.Second)) {
		return fail("observation time")
	}
	fresh, e := releasefeedobserver.Observe(releasefeedobserver.Context{Head: r.Head, Tree: r.Tree, SourceOwnerMessage: r.SourceOwnerMessage, ObservedAt: observed}, files)
	if e != nil || (!bytes.Equal(fresh, receipt) && !bytes.Equal(append(bytes.Clone(fresh), '\n'), receipt)) {
		return fail("observation bytes no longer match")
	}
	prepared, e := releasefeedwire.Prepare(p.Claims, files["release.json"], receipt)
	if e != nil {
		return fail("wire claims")
	}
	issued, _ := time.Parse("2006-01-02T15:04:05Z", p.Claims.IssuedAt)
	expires, _ := time.Parse("2006-01-02T15:04:05Z", p.Claims.ExpiresAt)
	due, e := time.Parse("2006-01-02T15:04:05Z", p.SuccessorDueAt)
	// An issuer never creates already-expired entries. The reader's additional
	// 300-second grace is a consumption rule, not permission to issue stale data.
	if now.Before(issued.Add(-300*time.Second)) || !now.Before(expires) || e != nil || !due.After(now) || due.After(expires) {
		return fail("issuance/expiry/successor window")
	}
	signature := ed25519.Sign(key, prepared.SigningBytes())
	att, e := prepared.Attestation(signature)
	if e != nil {
		return fail("attestation framing")
	}
	result := Bundle{EntryID: prepared.EntryID(), Purpose: p.Purpose, Files: map[string][]byte{}}
	for n, b := range files {
		result.Files[n] = bytes.Clone(b)
	}
	result.Files["attestation.bin"] = att
	result.Files["receipt.json"] = bytes.Clone(receipt)
	return result, nil
}
