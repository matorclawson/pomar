package codexseat

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func resetFixture(t *testing.T) (Supervisor, ResetRequest, string) {
	s := fixture(t)
	if err := s.write(pending(s)); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(s.StateDir, "actor.lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	data, _ := os.ReadFile(filepath.Join(s.StateDir, "codex-thread.json"))
	sha := sha256.Sum256(data)
	archive := filepath.Join(t.TempDir(), "owner-receipts")
	return s, ResetRequest{OperationID: "abandon-first", RecordSHA256: hex.EncodeToString(sha[:]), AcknowledgeUnknown: true}, archive
}
func TestOwnerAbandonArchivesUnknownAndIsIdempotent(t *testing.T) {
	s, req, archive := resetFixture(t)
	uid := uint32(os.Getuid())
	r, err := s.abandonStart(req, archive, uid, uid)
	if err != nil || r.Effects != "UNKNOWN_NOT_RETRIED" {
		t.Fatal(r, err)
	}
	if _, err = os.Stat(filepath.Join(s.StateDir, "codex-thread.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("original pointer not cleared")
	}
	again, err := s.abandonStart(req, archive, uid, uid)
	if err != nil || again != r {
		t.Fatal("lost same operation receipt", err)
	}
	req.RecordSHA256 = LinuxExecutableSHA256
	if _, err = s.abandonStart(req, archive, uid, uid); err == nil {
		t.Fatal("conflicting reset accepted")
	}
	files, _ := filepath.Glob(filepath.Join(archive, "*.original.json"))
	if len(files) != 1 {
		t.Fatal("original evidence not retained")
	}
}
func TestCodingUserCannotInvokeOwnerAbandon(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test requires actual nonroot user")
	}
	s, req, archive := resetFixture(t)
	if _, err := s.AbandonStart(req, archive); err == nil {
		t.Fatal("coding user bypassed real VM owner check")
	}
}
func TestOwnerAbandonRefusesRecordMismatchRolloutAndLiveLock(t *testing.T) {
	for _, kind := range []string{"digest", "rollout", "lock"} {
		t.Run(kind, func(t *testing.T) {
			s, req, archive := resetFixture(t)
			uid := uint32(os.Getuid())
			switch kind {
			case "digest":
				req.RecordSHA256 = LinuxExecutableSHA256
			case "rollout":
				rollout(t, s, "unbound", id1, "cli")
			case "lock":
				f, _ := os.OpenFile(filepath.Join(s.StateDir, "actor.lock"), os.O_RDWR, 0)
				defer f.Close()
				syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			}
			if _, err := s.abandonStart(req, archive, uid, uid); err == nil {
				t.Fatal("unsafe abandon accepted")
			}
			if _, err := os.Stat(filepath.Join(s.StateDir, "codex-thread.json")); err != nil {
				t.Fatal("held evidence removed")
			}
		})
	}
}

func TestOwnerTransactionSurvivesMissingFinalReceipt(t *testing.T) {
	s, req, archive := resetFixture(t)
	uid := uint32(os.Getuid())
	first, err := s.abandonStart(req, archive, uid, uid)
	if err != nil {
		t.Fatal(err)
	}
	id := sha256.Sum256([]byte(req.OperationID))
	name := hex.EncodeToString(id[:])
	if err = os.Remove(filepath.Join(archive, name+".receipt.json")); err != nil {
		t.Fatal(err)
	}
	again, err := s.abandonStart(req, archive, uid, uid)
	if err != nil || again != first {
		t.Fatal("owner recovery lost its original transaction", err)
	}
}
