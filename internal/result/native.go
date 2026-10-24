package result

// sow: pomar-SOW-90. Native attestations do not share the raw-result or
// closure signature domain. This file adds no key loader, receiver or caller.
import (
	"crypto/ed25519"
	"errors"
)

const NativeSchema = "pomar.native-artifact/v1"
const NativeSignatureContext = NativeSchema + "\x00"
const NativeMaxDocumentBytes = 64 * 1024

var ErrNativeIncomplete = errors.New("result: incomplete native attestation pair")

const nativeDocName = "native-artifact.json"
const nativeSigName = "native-artifact.json.sig"

func nativeMessage(doc []byte) []byte {
	message := make([]byte, len(NativeSignatureContext)+len(doc))
	copy(message, NativeSignatureContext)
	copy(message[len(NativeSignatureContext):], doc)
	return message
}

// SignNative signs already frozen trusted collector bytes. It does not validate
// observations or adopt a signing purpose. Only the protected receiver may call
// it after its actual observer, policy and original authority are verified.
// No executable caller is connected by this source slice.
func (s *Signer) SignNative(doc []byte) []byte {
	return s.Sign(nativeMessage(doc))
}

// VerifyNative checks the exact bytes in the native domain. The consumer must
// separately enforce its independently pinned schema, policy and purpose.
func VerifyNative(pub ed25519.PublicKey, doc, sig []byte) bool {
	return Verify(pub, nativeMessage(doc), sig)
}

// PublishNative reuses immutable, no-follow, pinned-directory publication.
// Retrying the same original frozen pair recovers an interrupted publication;
// changed bytes refuse. Persistence is not execution or resource acceptance.
func PublishNative(dir string, doc, sig []byte) error {
	if len(doc) == 0 || len(doc) > NativeMaxDocumentBytes || len(sig) != ed25519.SignatureSize {
		return ErrNativeIncomplete
	}
	return publishPair(dir, nativeDocName, nativeSigName, doc, sig)
}

func ReadNative(dir string) (doc, sig []byte, err error) {
	doc, sig, err = readPair(dir, nativeDocName, nativeSigName)
	if err == nil && (len(doc) == 0 || len(doc) > NativeMaxDocumentBytes || len(sig) != ed25519.SignatureSize) {
		err = ErrNativeIncomplete
	}
	return doc, sig, err
}
