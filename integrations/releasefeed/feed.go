// Package releasefeed verifies entries from owner-selected signed release feeds.
// Producers and transport implementations are independent of Pomar.
package releasefeed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"regexp"
	"time"
)

const MaxManifestBytes = 128 << 10

var producerID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)

// Entry is a producer's original manifest and detached signature.
type Entry struct {
	Producer  string
	Sequence  uint64
	IssuedAt  int64 // Unix seconds, inclusive.
	ExpiresAt int64 // Unix seconds, exclusive.
	Manifest  []byte
	Signature []byte
}

// Source fetches one exact sequence and must honor context cancellation. The
// adapter is responsible for bounding the transport before allocating an entry.
type Source interface {
	Lookup(ctx context.Context, sequence uint64) (Entry, error)
}

// Trust is supplied out of band by the owner. A Source cannot pick its own key
// or substitute a different producer.
type Trust struct {
	Producer  string
	PublicKey ed25519.PublicKey
}

// SigningBytes binds a producer, sequence and validity interval to the exact
// original manifest.
// The domain and length-prefixed fields keep other protocols and field splits
// from producing the same signed bytes.
func SigningBytes(entry Entry) ([]byte, error) {
	if !producerID.MatchString(entry.Producer) || entry.Sequence == 0 ||
		entry.IssuedAt <= 0 || entry.ExpiresAt <= entry.IssuedAt ||
		len(entry.Manifest) == 0 || len(entry.Manifest) > MaxManifestBytes {
		return nil, errors.New("invalid release entry binding, validity interval or manifest size")
	}
	b := []byte("pomar.signed-release-feed/v1\x00")
	b = binary.BigEndian.AppendUint16(b, uint16(len(entry.Producer)))
	b = append(b, entry.Producer...)
	b = binary.BigEndian.AppendUint64(b, entry.Sequence)
	b = binary.BigEndian.AppendUint64(b, uint64(entry.IssuedAt))
	b = binary.BigEndian.AppendUint64(b, uint64(entry.ExpiresAt))
	b = binary.BigEndian.AppendUint32(b, uint32(len(entry.Manifest)))
	return append(b, entry.Manifest...), nil
}

// Read verifies one explicitly selected release against independent trust for
// historical inspection. Activation requires Activate, which checks the signed
// validity interval and durably advances the producer's sequence before use.
func Read(ctx context.Context, src Source, trust Trust, sequence uint64) (Entry, error) {
	if src == nil || !producerID.MatchString(trust.Producer) ||
		len(trust.PublicKey) != ed25519.PublicKeySize || sequence == 0 {
		return Entry{}, errors.New("missing independent release feed binding")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	entry, err := src.Lookup(ctx, sequence)
	if err != nil {
		return Entry{}, err
	}
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	if entry.Producer != trust.Producer || entry.Sequence != sequence || len(entry.Signature) != ed25519.SignatureSize ||
		len(entry.Manifest) == 0 || len(entry.Manifest) > MaxManifestBytes {
		return Entry{}, errors.New("release entry differs from expected binding")
	}
	entry.Manifest = bytes.Clone(entry.Manifest)
	entry.Signature = bytes.Clone(entry.Signature)
	signed, err := SigningBytes(entry)
	if err != nil {
		return Entry{}, err
	}
	if !ed25519.Verify(trust.PublicKey, signed, entry.Signature) {
		return Entry{}, errors.New("release signature verification failed")
	}
	return entry, nil
}
