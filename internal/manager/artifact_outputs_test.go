package manager

import (
	"bytes"
	"encoding/json"
	"github.com/zeroemployeeorg/pomar/internal/artifactreturn"
	"github.com/zeroemployeeorg/pomar/internal/capacity"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func artifactClassForTest() capacity.Class {
	c := capacity.CI
	c.OutputCapBytes = 8
	c.ArtifactOutput = &artifactreturn.Policy{PerFileBytes: 4, MaxFiles: 2, TransferSeconds: 10, Names: []string{"one", "two"}, Provisional: true}
	return c
}
func TestArtifactHelperArgsDoNotExpandLegacyDefaults(t *testing.T) {
	old := capacity.CI
	old.OutputCapBytes = 0
	if !reflect.DeepEqual(classOutputArgs("/rec", []string{"one"}, old), outputArgs("/rec", []string{"one"}, 0)) {
		t.Fatal("legacy transport changed")
	}
	c := artifactClassForTest()
	c.OutputCapBytes = 128 << 20
	c.ArtifactOutput.PerFileBytes = 100 << 20
	args := strings.Join(classOutputArgs("/rec", c.ArtifactOutput.Names, c), " ")
	for _, want := range []string{"--outputs-max 134217728", "--artifact-output-per-file 104857600", "--artifact-output-timeout 10"} {
		if !strings.Contains(args, want) {
			t.Fatal("explicit class bound missing", args)
		}
	}
	c.ArtifactOutput = nil
	if outputLimit(c.OutputCapBytes) != 0 {
		t.Fatal("legacy cap expanded")
	}
}
func TestArtifactHashRefusesOverCapSymlinkAndHardlink(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	os.WriteFile(file, []byte("abc"), 0600)
	if _, _, e := hashArtifact(file, 2); e == nil {
		t.Fatal("over-cap file accepted")
	}
	link := filepath.Join(dir, "link")
	os.Symlink(file, link)
	if _, _, e := hashArtifact(link, 4); e == nil {
		t.Fatal("symlink accepted")
	}
	hard := filepath.Join(dir, "hard")
	os.Link(file, hard)
	if _, _, e := hashArtifact(hard, 4); e == nil {
		t.Fatal("hardlink accepted")
	}
	data, e := os.ReadFile(file)
	if e != nil || string(data) != "abc" {
		t.Fatal("original modified")
	}
}
func TestArtifactFinishSignsWholeSetAndNeverServesPartial(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "partial", true: "complete"}[complete], func(t *testing.T) {
			m, ctl, v := openSigning(t, false)
			id := "art-1"
			rec := filepath.Join(v.Root(), attemptsDir, id)
			os.MkdirAll(filepath.Join(rec, outputsDir), 0700)
			os.WriteFile(filepath.Join(rec, outputsDir, "one"), []byte("abc"), 0600)
			if complete {
				os.WriteFile(filepath.Join(rec, outputsDir, "two"), []byte("xyz"), 0600)
			}
			e := terminalEntry(id)
			e.ResultPolicy = m.resultPolicy()
			e.Class = artifactClassForTest()
			e.State, e.ExitCode, e.OutputNames = StateRunning, nil, []string{"one", "two"}
			m.mu.Lock()
			m.t.entries[id] = &e
			m.mu.Unlock()
			code := 0
			m.finish(id, StateExited, "", &code)
			var reply ResultReply
			if err := ctl.Do("GET", "/v1/attempts/"+id+"/result", nil, &reply); err != nil {
				t.Fatal(err)
			}
			var doc struct {
				State State          `json:"state"`
				Count int            `json:"artifact_output_count"`
				Class capacity.Class `json:"class"`
			}
			if err := json.Unmarshal(reply.Result, &doc); err != nil || doc.Count != 2 || doc.Class.ArtifactOutput == nil {
				t.Fatalf("signed artifact policy/count missing: %+v %v", doc, err)
			}
			var output bytes.Buffer
			_, err := ctl.Output(id, "one", &output)
			if complete {
				if err != nil || output.String() != "abc" || doc.State != StateExited {
					t.Fatal("complete set not served", err)
				}
			} else {
				if err == nil || output.Len() != 0 || doc.State != StateFailed {
					t.Fatal("partial set served as accepted", err)
				}
			}
		})
	}
}
