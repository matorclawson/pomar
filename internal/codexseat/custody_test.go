package codexseat

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestHomeRootSurvivesPathReplacementWithoutFollowingOutside(t *testing.T) {
	s := fixture(t)
	rollout(t, s, "original", id1, "cli")
	root, err := s.openHome()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	old := s.Home + "-retained"
	if err := os.Rename(s.Home, old); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, s.Home); err != nil {
		t.Fatal(err)
	}
	f, err := root.Open("sessions/original.jsonl")
	if err != nil {
		t.Fatal("retained root lost after path replacement", err)
	}
	f.Close()
	if _, err := root.Open("secret"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("followed replaced home", err)
	}
	if err := os.Symlink(outside, filepath.Join(old, "escape")); err != nil {
		t.Fatal(err)
	}
	if f, err := root.Open("escape/secret"); err == nil {
		f.Close()
		t.Fatal("escaped anchored root")
	}
	if _, err := s.bind(pending(s)); err == nil {
		t.Fatal("new binding accepted redirected home")
	}
}

func TestTrampolinesRefuseDeveloperOrRootIdentityBeforeExec(t *testing.T) {
	if os.Getuid() != 1000 || os.Geteuid() != 1000 || os.Getgid() != 1000 || os.Getegid() != 1000 {
		if err := checkActorIDs(); err == nil {
			t.Fatal("wrong real/effective actor identity accepted")
		}
		if err := ExecPinned([]string{"/must-not-execute"}); err == nil {
			t.Fatal("wrong actor identity reached exec")
		}
	}
	if os.Getuid() != ConsoleUID || os.Geteuid() != ConsoleUID {
		if err := ExecCustodian([]string{"/usr/bin/tmux", "-V"}); err == nil {
			t.Fatal("wrong custodian identity reached exec")
		}
	}
}

func TestActorHasSeparateControllingSessionAndNoFenceDescriptor(t *testing.T) {
	s := fixture(t)
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := s.nativeCommand("/fixed/guest", pending(s), f)
	attr := cmd.SysProcAttr
	if !attr.Setsid || !attr.Setctty || attr.Ctty != 0 {
		t.Fatal("actor shares the idle console's controlling terminal", attr)
	}
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != f {
		t.Fatal("actor inherited broker state")
	}
	if attr.Credential == nil || attr.Credential.Uid != 1000 || attr.Credential.Gid != 1000 {
		t.Fatal("missing actor identity")
	}
	if syscall.Getuid() == ConsoleUID {
		t.Fatal("fixture unexpectedly runs as the terminal custodian")
	}
}
