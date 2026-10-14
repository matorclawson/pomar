//go:build darwin || linux

// Package providerfence is the durable identity fence for the proposed native
// provider. It does not launch a process, authorize a caller, provision a UID,
// or prove capacity, clock quality, containment or quiescence. A custodian must
// qualify those gates independently before using a first-start decision.
package providerfence

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"syscall"
	"time"
)

const maxBytes = 1 << 20
const maxRecords = 2048 // Full namespaces refuse new IDs; they never evict fences.

var identity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Phase string

const (
	Reserved  Phase = "RESERVED"
	Starting  Phase = "STARTING"
	Unknown   Phase = "UNKNOWN"
	Expired   Phase = "EXPIRED"
	Abandoned Phase = "ABANDONED"
)

// BindingDigest is the digest of the complete, independently validated request,
// including principal/seat/SOW, source, tools, resources and execution profile.
// This package never substitutes an attempt ID for that binding.
type Record struct {
	ID            string    `json:"id"`
	BindingDigest string    `json:"binding_digest"`
	Incarnation   string    `json:"incarnation"`
	Token         string    `json:"token,omitempty"`
	Phase         Phase     `json:"phase"`
	Expires       time.Time `json:"expires"`
}

type state struct {
	Schema      string            `json:"schema"`
	Namespace   string            `json:"namespace"`
	Incarnation string            `json:"incarnation"`
	Retired     []string          `json:"retired_incarnations"`
	Records     map[string]Record `json:"records"`
}

type Store struct {
	root        *os.Root
	namespace   string
	incarnation string
	now         func() time.Time
}

// Open requires an existing private directory owned by the calling custodian.
// Changing incarnation permanently fences old handles, expires unstarted
// reservations and retains STARTING as UNKNOWN. Nothing is resumed by absence
// of a PID, nor is UNKNOWN released by lease expiry.
func Open(dir, namespace, incarnation string, now func() time.Time) (*Store, error) {
	if !identity.MatchString(namespace) || !identity.MatchString(incarnation) || now == nil {
		return nil, errors.New("invalid namespace, incarnation or clock")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || owner(info) != os.Geteuid() {
		return nil, errors.New("custodian directory must be owned and private")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	d, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	actual, statErr := d.Stat()
	d.Close()
	if statErr != nil || !os.SameFile(info, actual) {
		root.Close()
		return nil, errors.New("custodian directory changed")
	}
	s := &Store{root, namespace, incarnation, now}
	err = s.transaction(true, func(st *state) error {
		if st.Incarnation == incarnation {
			return nil
		}
		for _, old := range st.Retired {
			if old == incarnation {
				return errors.New("retired incarnation cannot be reused")
			}
		}
		if st.Incarnation != "" {
			st.Retired = append(st.Retired, st.Incarnation)
		}
		if len(st.Retired) > maxRecords {
			return errors.New("incarnation fence capacity exhausted")
		}
		for id, r := range st.Records {
			switch r.Phase {
			case Reserved:
				r.Phase, r.Token = Expired, ""
			case Starting:
				r.Phase = Unknown
			}
			st.Records[id] = r
		}
		st.Incarnation = incarnation
		return nil
	})
	if err != nil {
		root.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.root.Close() }

func (s *Store) Reserve(id, binding string, lease time.Duration) (Record, error) {
	var out Record
	if !identity.MatchString(id) || !digest.MatchString(binding) || lease <= 0 || lease > 30*time.Second {
		return out, errors.New("invalid identity, binding or lease")
	}
	err := s.transaction(false, func(st *state) error {
		if r, ok := st.Records[id]; ok {
			if r.BindingDigest != binding {
				return errors.New("identity binding mismatch")
			}
			out = r // Exact replay never renews or recreates a reservation.
			return nil
		}
		if len(st.Records) >= maxRecords {
			return errors.New("identity fence capacity exhausted")
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		out = Record{id, binding, s.incarnation, hex.EncodeToString(b), Reserved, s.now().UTC().Add(lease)}
		st.Records[id] = out
		return nil
	})
	return out, err
}

// Start commits STARTING durably before returning first=true. A replay returns
// first=false even if the first response was lost. A failed write may have
// committed: callers must reconcile the original ID, never try another ID.
func (s *Store) Start(id, binding, token string) (out Record, first bool, err error) {
	err = s.transaction(false, func(st *state) error {
		r, ok := st.Records[id]
		if !ok || r.BindingDigest != binding || r.Token != token || token == "" || r.Incarnation != s.incarnation {
			return errors.New("unknown or mismatched claim")
		}
		switch r.Phase {
		case Reserved:
			r.Phase = Starting
			st.Records[id] = r
			first = true
		case Starting, Unknown:
			// Replay is an observation, never permission for another execution.
		default:
			return errors.New("claim is fenced")
		}
		out = r
		return nil
	})
	if err != nil {
		first = false
	}
	return
}

// Abandon fences even an unseen ID under the same lock as Start. STARTING and
// UNKNOWN cannot be declared never-started or freed by this operation.
func (s *Store) Abandon(id, binding string) (Record, error) {
	var out Record
	if !identity.MatchString(id) || !digest.MatchString(binding) {
		return out, errors.New("invalid identity or binding")
	}
	err := s.transaction(false, func(st *state) error {
		r, ok := st.Records[id]
		if ok && r.BindingDigest != binding {
			return errors.New("identity binding mismatch")
		}
		if ok && (r.Phase == Starting || r.Phase == Unknown) {
			return errors.New("started claim requires custodian reconciliation")
		}
		if !ok {
			if len(st.Records) >= maxRecords {
				return errors.New("identity fence capacity exhausted")
			}
			r = Record{ID: id, BindingDigest: binding, Incarnation: s.incarnation}
		}
		r.Phase, r.Token = Abandoned, ""
		st.Records[id], out = r, r
		return nil
	})
	return out, err
}

func (s *Store) Lookup(id string) (Record, error) {
	var out Record
	err := s.transaction(false, func(st *state) error {
		var ok bool
		out, ok = st.Records[id]
		if !ok {
			return errors.New("identity not observed; not a never-start proof")
		}
		return nil
	})
	return out, err
}

func owner(info os.FileInfo) int { return int(info.Sys().(*syscall.Stat_t).Uid) }

func privateFile(f *os.File) error {
	i, err := f.Stat()
	if err != nil {
		return err
	}
	if !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || owner(i) != os.Geteuid() || i.Sys().(*syscall.Stat_t).Nlink != 1 {
		return errors.New("state file must be private, owned, regular and singly linked")
	}
	return nil
}

func (s *Store) transaction(opening bool, mutate func(*state) error) error {
	lock, err := s.root.OpenFile("lock", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	newLock := err == nil
	if errors.Is(err, os.ErrExist) {
		lock, err = s.root.OpenFile("lock", os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = privateFile(lock); err != nil {
		return err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	st := state{Schema: "pomar.provider-fence/v1", Namespace: s.namespace, Records: map[string]Record{}}
	f, err := s.root.OpenFile("state.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		defer f.Close()
		if err = privateFile(f); err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
		if err != nil || len(b) > maxBytes {
			return errors.New("state read failed or exceeds limit")
		}
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		st = state{} // Missing required fields cannot inherit initialization defaults.
		if err = decoder.Decode(&st); err != nil {
			return err
		}
		if err = decoder.Decode(new(any)); err != io.EOF {
			return errors.New("trailing state data")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if !opening || !newLock {
		return errors.New("missing state under existing fence; recovery required")
	}
	if st.Schema != "pomar.provider-fence/v1" || st.Namespace != s.namespace || st.Records == nil || len(st.Records) > maxRecords {
		return errors.New("state schema, namespace or bounds mismatch")
	}
	if !opening && st.Incarnation != s.incarnation {
		return errors.New("provider incarnation fenced")
	}
	for id, r := range st.Records {
		if id != r.ID || !identity.MatchString(id) || !digest.MatchString(r.BindingDigest) || !identity.MatchString(r.Incarnation) {
			return errors.New("invalid retained identity")
		}
		switch r.Phase {
		case Reserved, Starting, Unknown:
			if !digest.MatchString(r.Token) || r.Expires.IsZero() {
				return errors.New("invalid retained claim")
			}
		case Expired, Abandoned:
			if r.Token != "" {
				return errors.New("fenced claim retains token")
			}
		default:
			return errors.New("unknown retained phase")
		}
		if r.Phase == Reserved && !s.now().Before(r.Expires) {
			r.Phase, r.Token = Expired, ""
			st.Records[id] = r
		}
	}
	// Persist expiry even if the requested mutation is refused.
	operationErr := mutate(&st)
	if err = s.save(st); err != nil {
		return err
	}
	return operationErr
}

func (s *Store) save(st state) error {
	b, err := json.Marshal(st)
	if err != nil || len(b) > maxBytes {
		return errors.New("state encoding failed or exceeds limit")
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".pending-" + hex.EncodeToString(nonce[:])
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer s.root.Remove(name)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = s.root.Rename(name, "state.json"); err != nil {
		return err
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("state replaced; directory sync uncertain: %w", err)
	}
	return nil
}
