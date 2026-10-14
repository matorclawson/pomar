package codexseat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

type ResetRequest struct {
	OperationID        string `json:"operation_id"`
	RecordSHA256       string `json:"record_sha256"`
	AcknowledgeUnknown bool   `json:"acknowledge_unknown"`
}
type ResetReceipt struct {
	Schema      string `json:"schema"`
	OperationID string `json:"operation_id"`
	PriorSHA256 string `json:"prior_sha256"`
	Disposition string `json:"disposition"`
	Effects     string `json:"effects"`
	ObservedAt  string `json:"observed_at"`
}

// AbandonStart is an attended VM-owner action on the private root broker.
// Coding-user tools cannot invoke it; original evidence is archived separately
// in custodian-owned storage. It never claims that unknown effects succeeded.
func (s Supervisor) AbandonStart(req ResetRequest, archive string) (ResetReceipt, error) {
	if os.Geteuid() != 0 {
		return ResetReceipt{}, errors.New("unbound-start abandonment requires the VM owner")
	}
	return s.abandonStart(req, archive, 1000, 0)
}

func ownedDir(path string, uid uint32) error {
	if !filepath.IsAbs(path) {
		return errors.New("private directory must be absolute")
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return ErrHeld
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid {
		return ErrHeld
	}
	return nil
}

// ownerUID parameters are internal fixture/custody checks; the public entry
// above fixes the real guest owner IDs and performs the actual euid check.
func (s Supervisor) abandonStart(req ResetRequest, archive string, guestUID, ownerUID uint32) (ResetReceipt, error) {
	var receipt ResetReceipt
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`).MatchString(req.OperationID) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(req.RecordSHA256) || !req.AcknowledgeUnknown {
		return receipt, ErrHeld
	}
	if err := ownedDir(s.StateDir, guestUID); err != nil {
		return receipt, err
	}
	if err := ownedDir(s.Home, guestUID); err != nil {
		return receipt, err
	}
	if err := os.MkdirAll(archive, 0700); err != nil {
		return receipt, err
	}
	if err := ownedDir(archive, ownerUID); err != nil {
		return receipt, err
	}
	ar, err := os.OpenRoot(archive)
	if err != nil {
		return receipt, err
	}
	defer ar.Close()
	id := sha256.Sum256([]byte(req.OperationID))
	name := hex.EncodeToString(id[:])
	if data, e := ar.ReadFile(name + ".receipt.json"); e == nil {
		if json.Unmarshal(data, &receipt) != nil || receipt.OperationID != req.OperationID || receipt.PriorSHA256 != req.RecordSHA256 {
			return ResetReceipt{}, ErrHeld
		}
		return receipt, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return receipt, e
	}
	lock, err := os.OpenFile(filepath.Join(s.StateDir, "actor.lock"), os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return receipt, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return receipt, ErrActorRunning
	}
	// Resume only this owner transaction after a crash between unlink and
	// final receipt. Never clear a newer record or infer success of effects.
	if _, e := os.Lstat(filepath.Join(s.StateDir, "codex-thread.json")); errors.Is(e, os.ErrNotExist) {
		intent, e := ar.ReadFile(name + ".intent.json")
		if e != nil || json.Unmarshal(intent, &receipt) != nil || receipt.OperationID != req.OperationID || receipt.PriorSHA256 != req.RecordSHA256 {
			return ResetReceipt{}, ErrHeld
		}
		original, e := ar.ReadFile(name + ".original.json")
		if e != nil {
			return ResetReceipt{}, ErrHeld
		}
		hash := sha256.Sum256(original)
		if hex.EncodeToString(hash[:]) != req.RecordSHA256 {
			return ResetReceipt{}, ErrHeld
		}
		paths, e := s.rollouts()
		if e != nil || len(paths) != 0 {
			return ResetReceipt{}, ErrHeld
		}
		out, e := ar.OpenFile(name+".receipt.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return ResetReceipt{}, e
		}
		_, e = out.Write(intent)
		if e == nil {
			e = out.Sync()
		}
		out.Close()
		if e != nil {
			return ResetReceipt{}, e
		}
		d, e := ar.Open(".")
		if e != nil {
			return ResetReceipt{}, e
		}
		e = d.Sync()
		d.Close()
		return receipt, e
	}
	r, err := s.readAs(guestUID)
	if err != nil || r.State != "starting" || len(r.Before) != 0 {
		return receipt, ErrHeld
	}
	paths, err := s.rollouts()
	if err != nil || len(paths) != 0 {
		return receipt, ErrHeld
	}
	root, err := os.OpenRoot(s.StateDir)
	if err != nil {
		return receipt, err
	}
	defer root.Close()
	f, err := root.OpenFile("codex-thread.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return receipt, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		f.Close()
		return receipt, ErrHeld
	}
	data := make([]byte, info.Size())
	n, err := f.Read(data)
	f.Close()
	if err != nil || n != len(data) {
		return receipt, ErrHeld
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != req.RecordSHA256 {
		return receipt, ErrHeld
	}
	write := func(file string, body []byte) error {
		out, e := ar.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			if errors.Is(e, os.ErrExist) {
				old, readErr := ar.ReadFile(file)
				if readErr == nil && string(old) == string(body) {
					return nil
				}
			}
			return e
		}
		_, e = out.Write(body)
		if e == nil {
			e = out.Sync()
		}
		closeErr := out.Close()
		if e == nil {
			e = closeErr
		}
		return e
	}
	if err = write(name+".original.json", data); err != nil {
		return receipt, err
	}
	receipt = ResetReceipt{Schema: "pomar.codex-unbound-start-reset/v1", OperationID: req.OperationID, PriorSHA256: req.RecordSHA256, Disposition: "owner_abandoned_unbound_start", Effects: "UNKNOWN_NOT_RETRIED", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if old, e := ar.ReadFile(name + ".intent.json"); e == nil {
		if json.Unmarshal(old, &receipt) != nil || receipt.OperationID != req.OperationID || receipt.PriorSHA256 != req.RecordSHA256 {
			return ResetReceipt{}, ErrHeld
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return ResetReceipt{}, e
	}
	body, _ := json.Marshal(receipt)
	if err = write(name+".intent.json", body); err != nil {
		return ResetReceipt{}, err
	}
	ad, err := ar.Open(".")
	if err != nil {
		return ResetReceipt{}, err
	}
	err = ad.Sync()
	ad.Close()
	if err != nil {
		return ResetReceipt{}, err
	}
	// A different record or redirected path cannot be removed by a stale request.
	current, err := root.Lstat("codex-thread.json")
	if err != nil || !os.SameFile(info, current) {
		return ResetReceipt{}, ErrHeld
	}
	if err = root.Remove("codex-thread.json"); err != nil {
		return ResetReceipt{}, err
	}
	sd, err := root.Open(".")
	if err != nil {
		return ResetReceipt{}, err
	}
	err = sd.Sync()
	sd.Close()
	if err != nil {
		return ResetReceipt{}, err
	}
	if err = write(name+".receipt.json", body); err != nil {
		return ResetReceipt{}, err
	}
	ad, err = ar.Open(".")
	if err != nil {
		return ResetReceipt{}, err
	}
	err = ad.Sync()
	ad.Close()
	return receipt, err
}

// InspectStartup is metadata-only and available only to the private VM owner.
func (s Supervisor) InspectStartup() (map[string]any, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("startup inspection requires the VM owner")
	}
	r, err := s.readAs(1000)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.StateDir, "codex-thread.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, err
	}
	sha := sha256.Sum256(data)
	return map[string]any{"state": r.State, "thread": r.Thread, "record_sha256": hex.EncodeToString(sha[:]), "effects": "UNKNOWN_NOT_INFERRED"}, nil
}
