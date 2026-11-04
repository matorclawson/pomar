// Package releasefeedwire constructs the frozen v1/revision 3 release-feed
// bytes. It performs no signing, key access, observation, policy adoption,
// sequence reservation, filesystem access or publication. A Prepared value is
// not evidence of an eligible release. The producer must authenticate its
// observations, resolve current protected policy and reserve its sequence
// before submitting these bytes to a separately admitted fixed-purpose signer.
package releasefeedwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

const (
	Domain              = "pomar-release-entry-v1"
	Repository          = "rodriveracom/zeoconnect"
	Filename            = "attestation.bin"
	MaxHeaderBytes      = 16384
	MaxManifestBytes    = 131072
	MaxReceiptBytes     = 1048576
	MaxAttestationBytes = 32768
	MaxGeneration       = uint64(1<<53 - 1)
)

var (
	keyID  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	refID  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	gitID  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
	stamp  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// Claims must come from the authenticated observer and adopted protected
// policies. Validation here checks the wire grammar, not their authority,
// freshness against an observer clock, current revocation or sequence custody.
type Claims struct {
	KeyID, IssuedAt, ExpiresAt, Head, Tree        string
	ReceiptRef, TargetProfile, TargetDigest       string
	Sequence, ProfileGeneration, PolicyGeneration uint64
	TrustGeneration, RevocationGeneration         uint64
}

// header deliberately has exactly the frozen 21 fields. Repository, domain,
// object format, entry id and byte bindings cannot be supplied as overrides.
type header struct {
	KeyID                string `json:"key_id"`
	Domain               string `json:"domain"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
	Repository           string `json:"repository"`
	ObjectFormat         string `json:"object_format"`
	Head                 string `json:"head"`
	Tree                 string `json:"tree"`
	Sequence             uint64 `json:"sequence"`
	EntryID              string `json:"entry_id"`
	ManifestLength       int    `json:"manifest_length"`
	ManifestSHA256       string `json:"manifest_sha256"`
	ReceiptLength        int    `json:"receipt_length"`
	ReceiptSHA256        string `json:"receipt_sha256"`
	ReceiptRef           string `json:"receipt_ref"`
	ProfileGeneration    uint64 `json:"profile_generation"`
	PolicyGeneration     uint64 `json:"policy_generation"`
	TargetProfile        string `json:"target_profile"`
	TargetDigest         string `json:"target_digest"`
	TrustGeneration      uint64 `json:"trust_generation"`
	RevocationGeneration uint64 `json:"revocation_generation"`
}

// Prepared holds an immutable snapshot of the constructed header and signing
// input. Its zero value cannot produce an attestation.
type Prepared struct {
	header, signingInput []byte
	entryID              string
}

func parseTime(value string) (time.Time, error) {
	if !stamp.MatchString(value) {
		return time.Time{}, fmt.Errorf("timestamp must be exact ASCII UTC seconds")
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || t.Year() < 1 {
		return time.Time{}, fmt.Errorf("invalid Gregorian UTC timestamp")
	}
	return t, nil
}

func hash(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// Prepare constructs the header and signature transcript from owner-received
// bytes. The caller must provide immutable inputs during the call. Manifest
// semantics and receipt/profile/target provenance require their own validators;
// their hashes alone are not qualification. Subsequent caller mutations cannot
// change the prepared bytes. There is no public key, private key or signer here.
func Prepare(c Claims, manifest, receipt []byte) (Prepared, error) {
	if !keyID.MatchString(c.KeyID) || !refID.MatchString(c.ReceiptRef) || !refID.MatchString(c.TargetProfile) {
		return Prepared{}, fmt.Errorf("invalid opaque key, receipt or target identifier")
	}
	if !gitID.MatchString(c.Head) || !gitID.MatchString(c.Tree) || !digest.MatchString(c.TargetDigest) {
		return Prepared{}, fmt.Errorf("invalid Git object id or target digest")
	}
	if c.Sequence < 1 || c.Sequence > 999999 {
		return Prepared{}, fmt.Errorf("sequence outside 1..999999")
	}
	for _, n := range []uint64{c.ProfileGeneration, c.PolicyGeneration, c.TrustGeneration, c.RevocationGeneration} {
		if n < 1 || n > MaxGeneration {
			return Prepared{}, fmt.Errorf("generation outside exact JSON integer range")
		}
	}
	issued, err := parseTime(c.IssuedAt)
	if err != nil {
		return Prepared{}, err
	}
	expires, err := parseTime(c.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return Prepared{}, fmt.Errorf("expiry must be valid and strictly after issuance")
	}
	if len(manifest) < 1 || len(manifest) > MaxManifestBytes || len(receipt) < 1 || len(receipt) > MaxReceiptBytes {
		return Prepared{}, fmt.Errorf("manifest or receipt byte length outside wire bounds")
	}
	manifest = bytes.Clone(manifest)
	receipt = bytes.Clone(receipt)
	entryID := fmt.Sprintf("%06d-%s", c.Sequence, c.Head[:12])
	h := header{
		KeyID: c.KeyID, Domain: Domain, IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt,
		Repository: Repository, ObjectFormat: "sha1", Head: c.Head, Tree: c.Tree,
		Sequence: c.Sequence, EntryID: entryID,
		ManifestLength: len(manifest), ManifestSHA256: hash(manifest),
		ReceiptLength: len(receipt), ReceiptSHA256: hash(receipt), ReceiptRef: c.ReceiptRef,
		ProfileGeneration: c.ProfileGeneration, PolicyGeneration: c.PolicyGeneration,
		TargetProfile: c.TargetProfile, TargetDigest: c.TargetDigest,
		TrustGeneration: c.TrustGeneration, RevocationGeneration: c.RevocationGeneration,
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return Prepared{}, err
	}
	if len(raw) > MaxHeaderBytes || 8+len(raw)+64 > MaxAttestationBytes {
		return Prepared{}, fmt.Errorf("constructed header exceeds wire bounds")
	}
	return Prepared{header: raw, signingInput: signatureInput(raw, manifest), entryID: entryID}, nil
}

// signatureInput preserves the exact header bytes; reserializing would change
// the signed transcript. It is internal to the typed producer and vector tests.
func signatureInput(raw, manifest []byte) []byte {
	input := append([]byte(Domain), 0)
	input = binary.BigEndian.AppendUint32(input, uint32(len(raw)))
	input = append(input, raw...)
	input = binary.BigEndian.AppendUint64(input, uint64(len(manifest)))
	return append(input, manifest...)
}

func (p Prepared) HeaderBytes() []byte  { return bytes.Clone(p.header) }
func (p Prepared) SigningBytes() []byte { return bytes.Clone(p.signingInput) }
func (p Prepared) EntryID() string      { return p.entryID }

// Attestation frames a signature returned by the separately admitted signer.
// It checks only signature length, not cryptographic validity or signer trust.
// Consumers must verify against their independently adopted current trust.
func (p Prepared) Attestation(signature []byte) ([]byte, error) {
	if len(p.header) == 0 || len(p.signingInput) == 0 || len(signature) != 64 {
		return nil, fmt.Errorf("prepared input and exact 64-byte signature required")
	}
	out := append([]byte("PFA1"), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(p.header)))
	out = append(out, p.header...)
	out = append(out, signature...)
	return out, nil
}
