package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func exportFixture(t *testing.T) *os.Root {
	t.Helper()
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	os.WriteFile(filepath.Join(root.Name(), "tree.tar"), []byte("abc"), 0600)
	return root
}
func TestArtifactExportMatchesCrossLanguageWire(t *testing.T) {
	root := exportFixture(t)
	var out bytes.Buffer
	if e := exportArtifact(root, "tree.tar", 8, uint32(os.Geteuid()), &out); e != nil {
		t.Fatal(e)
	}
	golden, e := os.ReadFile("../../testdata/artifact-stream-v1.txt")
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(out.Bytes(), golden) {
		t.Fatal("wire differs from fixed cross-language fixture", out.String())
	}
}
func TestArtifactExportRefusesUnsafeFileOrLimitBeforeHeader(t *testing.T) {
	for _, kind := range []string{"size", "owner", "symlink", "hardlink", "path", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			root := exportFixture(t)
			name := "tree.tar"
			limit := int64(8)
			uid := uint32(os.Geteuid())
			switch kind {
			case "size":
				limit = 2
			case "owner":
				uid++
			case "symlink":
				root.Symlink("tree.tar", "alias")
				name = "alias"
			case "hardlink":
				root.Link("tree.tar", "alias")
				name = "alias"
			case "path":
				name = "../tree.tar"
			case "fifo":
				name = "pipe"
				if err := syscall.Mkfifo(filepath.Join(root.Name(), name), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			if e := exportArtifact(root, name, limit, uid, &out); e == nil || out.Len() != 0 {
				t.Fatal("unsafe file emitted protocol", e, out.String())
			}
		})
	}
}

type exportFailWriter struct{}

func (exportFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestArtifactExportDoesNotHideWriterFailure(t *testing.T) {
	root := exportFixture(t)
	if e := exportArtifact(root, "tree.tar", 8, uint32(os.Geteuid()), exportFailWriter{}); e == nil {
		t.Fatal("write failure ignored")
	}
}

type exportMutation struct {
	root *os.Root
	out  bytes.Buffer
	done bool
}

func (w *exportMutation) Write(p []byte) (int, error) {
	if !w.done && strings.HasPrefix(string(p), "POMAR_ARTIFACT_V1") {
		w.done = true
		os.WriteFile(filepath.Join(w.root.Name(), "tree.tar"), []byte("changed"), 0600)
	}
	return w.out.Write(p)
}
func TestArtifactExportMutationNeverEmitsCompletionFrame(t *testing.T) {
	root := exportFixture(t)
	out := &exportMutation{root: root}
	if e := exportArtifact(root, "tree.tar", 8, uint32(os.Geteuid()), out); e == nil {
		t.Fatal("changed artifact accepted")
	}
	if strings.Contains(out.out.String(), "POMAR_ARTIFACT_END") {
		t.Fatal("failed transfer emitted completion")
	}
}
