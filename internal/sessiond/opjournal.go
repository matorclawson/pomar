package sessiond

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// An adapter's effects are the agent's own, never pomar's to guarantee: the
// session layer's own guarantee is narrower and already true by
// construction (no input byte is ever replayed, no operation resubmitted
// by the layer itself). What an adapter needs on top of that, so a stop
// mid-effect and a resume don't repeat it, is a durable record of whether
// its own operation is known to have landed — the same primitive
// agentenv.Store's BeginControl/FinishControl already gives the headless
// broker (internal/agentenv/state.go), reused here in shape, not in code,
// for any adapter that can only speak over a session's PTY.
//
// An operation's disposition is pending, then sent (known committed) or
// acceptance_unknown (not known, and this is permanent: never silently
// resolved, never auto-retried, and never turned into success by a
// restart finding it still pending).

const (
	opPending           = "pending"
	opSent              = "sent"
	opAcceptanceUnknown = "acceptance_unknown"
)

// maxOpsPerSession bounds the distinct operation IDs one session's journal
// keeps. Past it, sent entries are evicted oldest first — never a pending
// or acceptance_unknown one, since those are exactly the ones that must
// survive. Under sustained adversarial pressure (everything held open),
// the bound is a soft cap, not a hard one: a session's own program cannot
// grow beyond the resources it has anyway.
const maxOpsPerSession = 4096

type opRecord struct {
	ID          string    `json:"id"`
	Digest      string    `json:"digest"`
	Disposition string    `json:"disposition"`
	At          time.Time `json:"at"`
}

type opEntry struct {
	digest      string
	disposition string
	at          time.Time
}

// HeldOp is one operation whose outcome is acceptance_unknown: shown so an
// attaching client sees it before typing anything, rather than treating
// "continue" as the reflex.
type HeldOp struct {
	ID      string `json:"id"`
	AgeSecs int64  `json:"age_seconds"`
}

// opJournal is one session's durable, per-operation disposition record: an
// append-only, fsynced file in the root, separate from both the shared
// metadata audit (journal.jsonl, which never carries operation digests)
// and the durable output log (which is exactly the program's bytes).
type opJournal struct {
	mu    sync.Mutex
	f     *os.File
	bound int // this instance's cap; a test shrinks it, never the shared constant
	ops   map[string]*opEntry
	order []string // insertion order, oldest first, for bound eviction
}

func opDir(root string) string { return filepath.Join(root, "ops") }

func opPath(root, id string) string { return filepath.Join(opDir(root), id+".jsonl") }

// openOpJournal opens (or creates) id's operation journal in root, private
// and append-only, and replays it: any operation left pending from before
// this open — a prior service never saw it finish — becomes
// acceptance_unknown now, durably, before anything can begin or finish
// against it. A restart can never make a pending operation look like it
// quietly became success.
func openOpJournal(root, id string) (*opJournal, error) {
	return openOpJournalBound(root, id, maxOpsPerSession)
}

// openOpJournalBound is openOpJournal with an explicit bound: a test's own
// instance, never a shared constant another test's journal could race.
func openOpJournalBound(root, id string, bound int) (*opJournal, error) {
	if err := os.MkdirAll(opDir(root), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(opPath(root, id), os.O_RDWR|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, errors.New("a session's operation journal must be a private regular file")
	}
	// A crash mid-write leaves a torn last line: bytes with no trailing
	// newline, from a write that never reached its own Sync. Left in
	// place, the NEXT append (this process, this open, or a future one)
	// lands directly after those torn bytes with no newline between them,
	// so the reader sees one garbled line spanning both the torn fragment
	// and the next, otherwise-complete record -- which fails to parse and
	// is skipped whole, silently losing that next record every time the
	// journal is replayed from then on. A lost begin makes a retry look
	// like a first attempt: double execution. Truncating any trailing,
	// newline-less bytes here, before this open's own first append, keeps
	// the file's on-disk end always a newline boundary, so this can't
	// recur.
	data, err := io.ReadAll(io.LimitReader(f, 64<<20))
	if err != nil {
		f.Close()
		return nil, err
	}
	clean := len(data)
	if clean > 0 && data[clean-1] != '\n' {
		clean = bytes.LastIndexByte(data, '\n') + 1 // 0 if none: the whole thing was torn
	}
	if clean < len(data) {
		if err := f.Truncate(int64(clean)); err != nil {
			f.Close()
			return nil, err
		}
	}
	j := &opJournal{f: f, bound: bound, ops: map[string]*opEntry{}}
	sc := bufio.NewScanner(bytes.NewReader(data[:clean]))
	sc.Buffer(make([]byte, 4096), 1<<20)
	for sc.Scan() {
		var r opRecord
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.ID == "" {
			continue // mid-file corruption, not a torn tail: skip, don't fail closed
		}
		if _, ok := j.ops[r.ID]; !ok {
			j.order = append(j.order, r.ID)
		}
		j.ops[r.ID] = &opEntry{digest: r.Digest, disposition: r.Disposition, at: r.At}
	}
	if err := j.convertPending(); err != nil {
		f.Close()
		return nil, err
	}
	return j, nil
}

// convertPending promotes every still-pending entry to acceptance_unknown,
// permanently: used both here, on open (a prior service never saw it
// finish), and when the session's own program exits (adapter.close) --
// nothing will ever call finish for it after that, since only that
// program's own adapter could have, and it's gone. Idempotent: an entry
// already past pending is untouched.
func (j *opJournal) convertPending() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, id := range j.order {
		e := j.ops[id]
		if e != nil && e.disposition == opPending {
			if err := j.appendLocked(id, e.digest, opAcceptanceUnknown); err != nil {
				return err
			}
			e.disposition = opAcceptanceUnknown
		}
	}
	return nil
}

func (j *opJournal) appendLocked(id, digest, disposition string) error {
	r := opRecord{ID: id, Digest: digest, Disposition: disposition, At: time.Now().UTC()}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := j.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return j.f.Sync()
}

// begin dedupes an adapter's operation by ID: a retry with the same digest
// returns first=false and does nothing; a different digest for the same ID
// is refused (ErrConflict-shaped, the same meaning BeginControl gives it).
// Anything that already exists, whatever its disposition, is a retry, not
// a fresh start: matching BeginControl's own behaviour.
func (j *opJournal) begin(id, digest string) (first bool, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if e, ok := j.ops[id]; ok {
		if e.digest != digest {
			return false, errors.New("this operation id already began with a different digest")
		}
		return false, nil
	}
	if err := j.appendLocked(id, digest, opPending); err != nil {
		return false, err
	}
	j.ops[id] = &opEntry{digest: digest, disposition: opPending, at: time.Now().UTC()}
	j.order = append(j.order, id)
	j.evictLocked()
	return true, nil
}

// finish records an operation's outcome, once: known commits it sent;
// !known leaves it acceptance_unknown, permanently — a later finish on the
// same id, known or not, is refused, never silently overwritten.
func (j *opJournal) finish(id string, known bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.ops[id]
	if !ok {
		return errors.New("this operation id was never begun")
	}
	if e.disposition != opPending {
		return errors.New("this operation already has a disposition; it is never overwritten")
	}
	disposition := opSent
	if !known {
		disposition = opAcceptanceUnknown
	}
	if err := j.appendLocked(id, e.digest, disposition); err != nil {
		return err
	}
	e.disposition = disposition
	return nil
}

// status reads an operation's disposition back, or "not_found".
func (j *opJournal) status(id string) string {
	j.mu.Lock()
	defer j.mu.Unlock()
	if e, ok := j.ops[id]; ok {
		return e.disposition
	}
	return "not_found"
}

// held lists every acceptance_unknown operation, oldest first.
func (j *opJournal) held() []HeldOp {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []HeldOp
	now := time.Now()
	for _, id := range j.order {
		if e := j.ops[id]; e != nil && e.disposition == opAcceptanceUnknown {
			out = append(out, HeldOp{ID: id, AgeSecs: int64(now.Sub(e.at).Seconds())})
		}
	}
	return out
}

// evictLocked drops sent entries, oldest first, once the session is over
// its bound. It never touches a pending or acceptance_unknown entry: the
// bound is soft when every entry is one of those.
func (j *opJournal) evictLocked() {
	if len(j.ops) <= j.bound {
		return
	}
	kept := j.order[:0]
	removed := len(j.ops) - j.bound
	for _, id := range j.order {
		if removed > 0 {
			if e := j.ops[id]; e != nil && e.disposition == opSent {
				delete(j.ops, id)
				removed--
				continue
			}
		}
		kept = append(kept, id)
	}
	j.order = kept
}

func (j *opJournal) close() { j.f.Close() }
