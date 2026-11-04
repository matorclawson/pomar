package releasefeedinput

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedRegularSnapshotAndSymlinkRefusal(t *testing.T) {
	d := t.TempDir()
	if e := os.WriteFile(filepath.Join(d, "artifact"), []byte("public data"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := os.OpenRoot(d)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	b, e := ReadRegular(r, "artifact", 32)
	if e != nil || string(b) != "public data" {
		t.Fatal(e)
	}
	if b, e := ReadRegular(r, "artifact", 2); e == nil || b != nil {
		t.Fatal("size bound bypass")
	}
	if e := os.Symlink("artifact", filepath.Join(d, "redirect")); e != nil {
		t.Fatal(e)
	}
	if b, e := ReadRegular(r, "redirect", 32); e == nil || b != nil {
		t.Fatal("symlink accepted")
	}
}
