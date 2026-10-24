package result

// sow: pomar-SOW-90. Synthetic keys and temporary records only; these controls
// do not establish an installed observer, protected identity or native run.
import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeSignatureDomainsAndFrozenBytes(t *testing.T) {
	// Deterministic fixture key: never loaded from a host identity store.
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Signer{priv: priv}
	doc := []byte(`{"schema":"pomar.native-artifact/v1","attempt":"original"}`)
	sig := s.SignNative(doc)
	if !VerifyNative(s.Public(), doc, sig) {
		t.Fatal("native signature refused")
	}
	if Verify(s.Public(), doc, sig) || VerifyClosure(s.Public(), doc, sig) {
		t.Fatal("native signature crossed into a legacy domain")
	}
	for _, foreign := range [][]byte{s.Sign(doc), s.SignClosure(doc)} {
		if VerifyNative(s.Public(), doc, foreign) {
			t.Fatal("legacy signature accepted as native")
		}
	}
	if VerifyNative(s.Public(), append(append([]byte(nil), doc...), ' '), sig) {
		t.Fatal("changed frozen bytes accepted")
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	if VerifyNative(other.Public().(ed25519.PublicKey), doc, sig) {
		t.Fatal("foreign key accepted")
	}
	for _, short := range [][]byte{nil, sig[:len(sig)-1]} {
		if VerifyNative(s.Public(), doc, short) {
			t.Fatal("incomplete signature accepted")
		}
	}
}

func TestNativeInterruptedPublicationAndLegacyEvidence(t *testing.T) {
	dir := t.TempDir()
	legacy, closure := []byte("legacy result"), []byte("legacy closure")
	if err := Publish(dir, legacy, []byte("result sig")); err != nil {
		t.Fatal(err)
	}
	if err := PublishClosure(dir, closure, []byte("closure sig")); err != nil {
		t.Fatal(err)
	}
	doc, sig := []byte("frozen native proof"), bytes.Repeat([]byte{7}, ed25519.SignatureSize)
	if err := os.WriteFile(filepath.Join(dir, nativeDocName), doc, 0400); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadNative(dir); err == nil {
		t.Fatal("document without signature reported complete")
	}
	if err := PublishNative(dir, doc, sig); err != nil {
		t.Fatal("same-original interrupted publication", err)
	}
	if err := PublishNative(dir, doc, sig); err != nil {
		t.Fatal("lost acknowledgement recovery", err)
	}
	for _, pair := range [][2][]byte{{[]byte("other original"), sig}, {doc, bytes.Repeat([]byte{8}, ed25519.SignatureSize)}} {
		if err := PublishNative(dir, pair[0], pair[1]); !errors.Is(err, ErrConflict) {
			t.Fatal("conflicting original accepted", err)
		}
	}
	got, proof, err := ReadNative(dir)
	if err != nil || !bytes.Equal(got, doc) || !bytes.Equal(proof, sig) {
		t.Fatal("native evidence changed", err)
	}
	got, proof, err = Read(dir)
	if err != nil || !bytes.Equal(got, legacy) || !bytes.Equal(proof, []byte("result sig")) {
		t.Fatal("legacy result changed", err)
	}
	got, proof, err = ReadClosure(dir)
	if err != nil || !bytes.Equal(got, closure) || !bytes.Equal(proof, []byte("closure sig")) {
		t.Fatal("closure changed", err)
	}
}

func TestNativeSymlinkCannotPublishOrReadForeignEvidence(t *testing.T) {
	for _, name := range []string{nativeDocName, nativeSigName} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			foreign := filepath.Join(t.TempDir(), "foreign")
			original := []byte("retained foreign bytes")
			if err := os.WriteFile(foreign, original, 0400); err != nil {
				t.Fatal(err)
			}
			if name == nativeSigName {
				if err := os.WriteFile(filepath.Join(dir, nativeDocName), []byte("proof"), 0400); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(foreign, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if err := PublishNative(dir, []byte("proof"), bytes.Repeat([]byte{7}, ed25519.SignatureSize)); !errors.Is(err, ErrConflict) {
				t.Fatal("symlink publication accepted", err)
			}
			if _, _, err := ReadNative(dir); err == nil {
				t.Fatal("symlink read accepted")
			}
			got, err := os.ReadFile(foreign)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("foreign evidence changed", err)
			}
		})
	}
}

func TestNativeUnsignedOrPartialPairIsNeverPublishedAsComplete(t *testing.T) {
	for _, sig := range [][]byte{nil, {}, []byte("short")} {
		dir := t.TempDir()
		if err := PublishNative(dir, []byte("frozen proof"), sig); !errors.Is(err, ErrNativeIncomplete) {
			t.Fatal("unsigned or partial native pair published", err)
		}
		if _, err := os.Lstat(filepath.Join(dir, nativeDocName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("incomplete request wrote native evidence", err)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, nativeDocName), []byte("retained partial proof"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, nativeSigName), []byte("partial signature"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadNative(dir); !errors.Is(err, ErrNativeIncomplete) {
		t.Fatal("partial retained signature was complete", err)
	}
	if err := PublishNative(dir, []byte("retained partial proof"), bytes.Repeat([]byte{7}, ed25519.SignatureSize)); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting partial signature overwritten", err)
	}
	retained, err := os.ReadFile(filepath.Join(dir, nativeSigName))
	if err != nil || string(retained) != "partial signature" {
		t.Fatal("partial evidence lost", err)
	}
}
