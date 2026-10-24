package result

// sow: pomar-SOW-87. Closure uses the same protected publication primitive.
import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestClosurePublicationIsSeparateImmutableAndRecoverable(t *testing.T) {
	dir := t.TempDir()
	original := []byte(`{"schema":"pomar.result/v1"}`)
	if err := Publish(dir, original, []byte("result-proof")); err != nil {
		t.Fatal(err)
	}
	doc := []byte(`{"schema":"pomar.closure/v1"}`)
	sig := []byte("closure-proof")
	if err := os.WriteFile(filepath.Join(dir, closureDocName), doc, 0400); err != nil {
		t.Fatal(err)
	}
	if err := PublishClosure(dir, doc, sig); err != nil {
		t.Fatal("document-only recovery", err)
	}
	if err := PublishClosure(dir, doc, sig); err != nil {
		t.Fatal("same-original retry", err)
	}
	if err := PublishClosure(dir, []byte("different"), sig); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting closure accepted", err)
	}
	got, proof, err := ReadClosure(dir)
	if err != nil || !bytes.Equal(got, doc) || !bytes.Equal(proof, sig) {
		t.Fatal("original changed", err)
	}
	got, proof, err = Read(dir)
	if err != nil || !bytes.Equal(got, original) || !bytes.Equal(proof, []byte("result-proof")) {
		t.Fatal("closure changed result wire/evidence", err)
	}
}
func TestClosureFinalSymlinkCannotAuthorizeOrModifyForeignEvidence(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "foreign")
	doc := []byte(`{"schema":"pomar.closure/v1"}`)
	if err := os.WriteFile(outside, doc, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, closureDocName)); err != nil {
		t.Fatal(err)
	}
	if err := PublishClosure(dir, doc, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("symlink publication accepted", err)
	}
	if _, _, err := ReadClosure(dir); !errors.Is(err, ErrConflict) {
		t.Fatal("symlink reader accepted", err)
	}
	if got, err := os.ReadFile(outside); err != nil || !bytes.Equal(got, doc) {
		t.Fatal("foreign evidence changed", err)
	}
}

func TestClosureSignatureCannotBeUsedAsResultSignature(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadOrCreate(dir, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	doc := []byte(`{"schema":"pomar.closure/v1","attempt":"original"}`)
	proof := signer.SignClosure(doc)
	if !VerifyClosure(signer.Public(), doc, proof) {
		t.Fatal("valid closure rejected")
	}
	if Verify(signer.Public(), doc, proof) {
		t.Fatal("closure accepted in raw result signature domain")
	}
	raw := signer.Sign(doc)
	if !Verify(signer.Public(), doc, raw) {
		t.Fatal("unchanged raw result signature rejected")
	}
	if VerifyClosure(signer.Public(), doc, raw) {
		t.Fatal("raw result signature accepted as closure")
	}
	if VerifyClosure(signer.Public(), append(append([]byte(nil), doc...), ' '), proof) {
		t.Fatal("changed closure bytes accepted")
	}
}
