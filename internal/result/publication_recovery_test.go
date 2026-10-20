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

// An os.Root contains path traversal, but deliberately resolves symlinks whose
// targets remain inside it. Final publication names must never be symlinks.
func TestPublicationRejectsInRecordFinalNameSymlinks(t *testing.T) {
	for _, name := range []string{DocName, SigName} {
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			doc, sig := []byte("frozen document"), []byte("frozen signature")
			if err := Publish(d, doc, sig); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(d, "retained-target")
			if err := os.Rename(filepath.Join(d, name), target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("retained-target", filepath.Join(d, name)); err != nil {
				t.Fatal(err)
			}
			if err := Publish(d, doc, sig); !errors.Is(err, ErrConflict) {
				t.Fatalf("symlink publication accepted: %v", err)
			}
			if _, _, err := Read(d); !errors.Is(err, ErrConflict) {
				t.Fatalf("symlink read accepted: %v", err)
			}
			st, err := os.Lstat(filepath.Join(d, name))
			if err != nil || st.Mode()&os.ModeSymlink == 0 {
				t.Fatal("conflicting symlink was replaced", err)
			}
			got, err := os.ReadFile(target)
			expected := doc
			if name == SigName {
				expected = sig
			}
			if err != nil || !bytes.Equal(got, expected) {
				t.Fatal("retained target changed", err)
			}
		})
	}
}

func TestRecordIdentityRejectsDifferentOpenedDirectory(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	original, err := os.Open(first)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	before, err := original.Stat()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(second)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := recordIdentity(root, before); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched rooted directory accepted: %v", err)
	}
	same, err := os.OpenRoot(first)
	if err != nil {
		t.Fatal(err)
	}
	defer same.Close()
	if err := recordIdentity(same, before); err != nil {
		t.Fatal("matching identity refused", err)
	}
}

func TestOpenRecordRefusesDirectorySubstitutedBetweenOpens(t *testing.T) {
	parent := t.TempDir()
	dir, saved, replacement := filepath.Join(parent, "record"), filepath.Join(parent, "saved"), filepath.Join(parent, "replacement")
	for _, name := range []string{dir, replacement} {
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := openRecordAfterGuard(dir, func() {
		if err := os.Rename(dir, saved); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, dir); err != nil {
			t.Fatal(err)
		}
	})
	if root != nil {
		root.Close()
	}
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("substituted directory passed actual two-open sequence: %v", err)
	}
	for _, name := range []string{dir, saved} {
		entries, err := os.ReadDir(name)
		if err != nil || len(entries) != 0 {
			t.Fatal("substitution wrote publication bytes", err)
		}
	}
}

func TestReadRegularRejectsSubstitutionBetweenOpenAndValidation(t *testing.T) {
	for _, name := range []string{DocName, SigName} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			approved, planted := []byte("frozen approved bytes"), []byte("planted bytes")
			if err := os.WriteFile(filepath.Join(dir, "approved"), approved, 0400); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "planted"), planted, 0400); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("planted", filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			got, err := readRegularAfterOpen(root, name, func() {
				// os.Root opened the in-record symlink's target. Before validation,
				// restore a regular approved final name: IsRegular alone now passes.
				if err := root.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := root.Rename("approved", name); err != nil {
					t.Fatal(err)
				}
			})
			if !errors.Is(err, ErrConflict) || len(got) != 0 {
				t.Fatalf("opened planted inode escaped validation: %q %v", got, err)
			}
			retained, err := root.ReadFile(name)
			if err != nil || !bytes.Equal(retained, approved) {
				t.Fatal("approved final name changed", err)
			}
		})
	}
}

func TestReadRegularRetainsTransientNamedStatError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DocName), []byte("frozen"), 0400); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	defer os.Chmod(dir, 0700)
	_, err = readRegularAfterOpen(root, DocName, func() {
		if err := os.Chmod(dir, 0000); err != nil {
			t.Fatal(err)
		}
	})
	if !errors.Is(err, os.ErrPermission) || errors.Is(err, ErrConflict) {
		t.Fatalf("transient Lstat refusal became conflicting evidence: %v", err)
	}
}

func TestReadRegularRefusesFinalNameRemovedAfterOpen(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DocName), []byte("frozen"), 0400); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := readRegularAfterOpen(root, DocName, func() {
		if err := root.Remove(DocName); err != nil {
			t.Fatal(err)
		}
	})
	if !errors.Is(err, ErrConflict) || len(got) != 0 {
		t.Fatalf("missing final name yielded a publication: %q %v", got, err)
	}
}
