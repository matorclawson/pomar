package result

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPublicationRecoversDocumentOnlyAndLostAcknowledgment(t *testing.T) {
	d := t.TempDir()
	doc := []byte(`{"original":"same"}`)
	sig := []byte("synthetic-proof")
	// Reproduces the old Write failure: the document is already present.
	if err := Write(d, doc, nil); err != nil {
		t.Fatal(err)
	}
	if err := Publish(d, doc, sig); err != nil {
		t.Fatalf("document-only recovery: %v", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := Publish(d, doc, sig); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	got, proof, err := Read(d)
	if err != nil || !bytes.Equal(got, doc) || !bytes.Equal(proof, sig) {
		t.Fatal("original bytes changed", err)
	}
	for _, n := range []string{DocName, SigName} {
		st, err := os.Stat(filepath.Join(d, n))
		if err != nil || st.Mode().Perm() != 0400 {
			t.Fatal(n, err)
		}
	}
	if err := Publish(d, []byte(`{"original":"different"}`), sig); !errors.Is(err, ErrConflict) {
		t.Fatal("conflict accepted", err)
	}
}

func TestPublicationRejectsForeignSignatureBeforeInstallingDocument(t *testing.T) {
	d := t.TempDir()
	foreign := []byte("retained-conflict")
	if err := os.WriteFile(filepath.Join(d, SigName), foreign, 0400); err != nil {
		t.Fatal(err)
	}
	if err := Publish(d, []byte("doc"), []byte("new")); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d, DocName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("document installed despite conflicting proof")
	}
	got, _ := os.ReadFile(filepath.Join(d, SigName))
	if !bytes.Equal(got, foreign) {
		t.Fatal("conflict overwritten")
	}
}

func TestPublicationRefusesSymlinkWithoutChangingTarget(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(d, DocName)); err != nil {
		t.Fatal(err)
	}
	if err := Publish(d, []byte("replacement"), nil); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "retained" {
		t.Fatal("target changed")
	}
}

func TestPublicationRefusesSymlinkRecordDirectory(t *testing.T) {
	outside := t.TempDir()
	link := filepath.Join(t.TempDir(), "record")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	err := Publish(link, []byte(`{"attempt":"original"}`), []byte("proof"))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("symlink record accepted: %v", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("publication wrote outside its record", err)
	}
}
