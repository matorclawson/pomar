//go:build darwin

package serviceupgrade

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestControlFenceNeverChangesSocketSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	run := filepath.Join(root, "run")
	if err := os.Mkdir(run, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(run, 0750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	data := []byte("unchanged outside service directory\n")
	if err := os.WriteFile(outside, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(run, "ctl.sock")); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0700, 0750, 0700} {
		if err := controlDirectoryMode(run, uint32(os.Getuid()), mode); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(run)
		if err != nil || st.Mode().Perm() != mode {
			t.Fatal(st, err)
		}
		st, err = os.Stat(outside)
		got, readErr := os.ReadFile(outside)
		if err != nil || st.Mode().Perm() != 0600 || readErr != nil || !bytes.Equal(got, data) {
			t.Fatal("socket symlink changed an outside file", st, err, readErr)
		}
	}
	alias := filepath.Join(root, "directory-alias")
	if err := os.Symlink(run, alias); err != nil {
		t.Fatal(err)
	}
	if err := controlDirectoryMode(alias, uint32(os.Getuid()), 0750); err == nil {
		t.Fatal("directory symlink accepted")
	}
	if err := controlDirectoryMode(run, uint32(os.Getuid())+1, 0750); err == nil {
		t.Fatal("foreign directory accepted")
	}
	st, _ := os.Stat(run)
	if st.Mode().Perm() != 0700 {
		t.Fatal("refused operation changed directory mode")
	}
}

func TestCodesignInlineRequirementOnRealAdHocBinary(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := exec.Command("/usr/bin/codesign", "--display", "--verbose=4", path).CombinedOutput()
	if err != nil || !isDevelopmentSignature(string(metadata)) {
		t.Fatal("test fixture is not actually ad-hoc signed", string(metadata), err)
	}
	identifier := ""
	for _, line := range strings.Split(string(metadata), "\n") {
		if strings.HasPrefix(line, "Identifier=") {
			identifier = strings.TrimPrefix(line, "Identifier=")
		}
	}
	if identifier == "" {
		t.Fatal("fixture identifier unavailable")
	}
	requirement := "identifier " + strconv.Quote(identifier)
	for _, test := range []struct {
		requirement string
		exit        int
	}{
		{inlineRequirement(requirement), 0},
		{inlineRequirement(`identifier "ac.zeo.pomar.wrong"`), 3},
		{inlineRequirement(requirement + ` and certificate leaf = H"1111111111111111111111111111111111111111"`), 3},
		{requirement, 1},
	} {
		out, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", "-R", test.requirement, path).CombinedOutput()
		exit := 0
		if err != nil {
			failure, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			exit = failure.ExitCode()
		}
		if exit != test.exit {
			t.Fatalf("requirement %q: exit %d, want %d: %s", test.requirement, exit, test.exit, out)
		}
		t.Logf("actual codesign requirement %q -> exit %d", test.requirement, exit)
	}
}

func TestRollbackArchiveChecksBothBinariesBeforeRecovery(t *testing.T) {
	path := t.TempDir()
	build := Build{Binaries: map[string]FilePin{}}
	for _, name := range binaries {
		data := []byte("original " + name + "\n")
		if err := os.WriteFile(filepath.Join(path, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		build.Binaries[name] = FilePin{digest(data), int64(len(data))}
	}
	if err := archivedBinaries(path, build, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "pomar-host"), []byte("corrupted archive\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := archivedBinaries(path, build, uint32(os.Getuid())); err == nil {
		t.Fatal("corrupted second recovery binary accepted")
	}
	lock, err := os.CreateTemp(t.TempDir(), "fake-lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	n := &Native{M: Manifest{Baseline: build}, ArchivePath: path, rollback: true, lock: lock}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = n.Restore(ctx, Journal{Archive: path})
	if err == nil || !strings.Contains(err.Error(), "archived pomar") {
		t.Fatal("archive was not refused before service commands", err)
	}
}
