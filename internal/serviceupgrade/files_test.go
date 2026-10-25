package serviceupgrade

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestBoundedFileReadRejectsIndirectionAndFIFO(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "file")
	if e := os.WriteFile(f, []byte("bounded"), 0600); e != nil {
		t.Fatal(e)
	}
	uid := uint32(os.Getuid())
	if b, e := readFile(f, 7, uid); e != nil || string(b) != "bounded" {
		t.Fatal(string(b), e)
	}
	if _, e := readFile(f, 6, uid); e == nil {
		t.Fatal("oversized accepted")
	}
	sy := filepath.Join(d, "symlink")
	if e := os.Symlink(f, sy); e != nil {
		t.Fatal(e)
	}
	if _, e := readFile(sy, 7, uid); e == nil {
		t.Fatal("symlink accepted")
	}
	hard := filepath.Join(d, "hardlink")
	if e := os.Link(f, hard); e != nil {
		t.Fatal(e)
	}
	if _, e := readFile(f, 7, uid); e == nil {
		t.Fatal("hardlinked file accepted")
	}
	fifo := filepath.Join(d, "fifo")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := readFile(fifo, 7, uid); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("fifo accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("fifo blocked")
	}
}

// A directory owner can replace the original pathname while the upgrader is
// root. The opened directory must remain the only destination for every effect.
func TestDurableWriteAnchorsEffectsAcrossDirectorySymlinkReplacement(t *testing.T) {
	d := t.TempDir()
	parent, moved, outside := filepath.Join(d, "manager"), filepath.Join(d, "retained"), filepath.Join(d, "outside")
	for _, p := range []string{parent, outside} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := filepath.Join(outside, "table.json")
	if err := os.WriteFile(sentinel, []byte("must remain unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, parent); err != nil {
		t.Fatal(err)
	}
	if err := durableWriteIn(root, "table.json", []byte("archived table"), 0600, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil || string(got) != "must remain unchanged" {
		t.Fatal("directory replacement redirected the write", string(got), err)
	}
	got, err = os.ReadFile(filepath.Join(moved, "table.json"))
	if err != nil || string(got) != "archived table" {
		t.Fatal("write did not stay in the opened directory", string(got), err)
	}
	if err := durableWriteOwned(filepath.Join(parent, "table.json"), []byte("refused"), 0600, uint32(os.Getuid())); err == nil {
		t.Fatal("initial symlink directory accepted")
	}
}

func TestDurableWriteDoesNotFollowDestinationSymlink(t *testing.T) {
	d := t.TempDir()
	sentinel, target := filepath.Join(d, "sentinel"), filepath.Join(d, "table.json")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, target); err != nil {
		t.Fatal(err)
	}
	if err := durableWriteOwned(target, []byte("replacement"), 0600, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil || string(got) != "untouched" {
		t.Fatal("followed destination symlink", string(got), err)
	}
	st, err := os.Lstat(target)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		t.Fatal("replacement is not an owned regular file", err)
	}
}
