package result

import "crypto/ed25519"

// sow: pomar-SOW-87. Closure is independent of the unchanged result/v1 wire.
// Only the trusted manager assembles and freezes this evidence. This package
// exposes no endpoint that imports manifests or signs actor-supplied claims.

const ClosureSchema = "pomar.closure/v1"
const CleanupSchema = "pomar.vm-cleanup/v1"

const closureDocName = "closure.json"
const closureSigName = "closure.json.sig"

// PublishClosure uses the same pinned record directory, no-follow immutable
// inode checks and directory synchronization as result publication. It never
// creates an unqualified nested parent or accepts a caller-selected filename.
func PublishClosure(dir string, doc, sig []byte) error {
	return publishPair(dir, closureDocName, closureSigName, doc, sig)
}

func ReadClosure(dir string) (doc, sig []byte, err error) {
	return readPair(dir, closureDocName, closureSigName)
}

// ReadHelperStatus is a bounded no-follow read of the fixed helper-owned file.
// It does not itself authenticate an attempt, process, or cleanup observation.
func ReadHelperStatus(dir string) ([]byte, error) {
	root, err := openRecord(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readRegular(root, "status.json")
}

// ClosureSignatureContext separates closure evidence from the unchanged raw
// result signature domain. Signatures cover these bytes, then the exact JSON.
const ClosureSignatureContext = "pomar.closure/v1\x00"

func closureMessage(doc []byte) []byte {
	message := make([]byte, len(ClosureSignatureContext)+len(doc))
	copy(message, ClosureSignatureContext)
	copy(message[len(ClosureSignatureContext):], doc)
	return message
}

// SignClosure signs trusted frozen closure bytes in their own domain.
func (s *Signer) SignClosure(doc []byte) []byte {
	return s.Sign(closureMessage(doc))
}

// VerifyClosure requires the closure domain; legacy raw signatures are refused.
func VerifyClosure(pub ed25519.PublicKey, doc, sig []byte) bool {
	return Verify(pub, closureMessage(doc), sig)
}
