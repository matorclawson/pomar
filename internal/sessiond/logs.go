package sessiond

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"

	"github.com/zeroemployeeorg/pomar/internal/seatterm"
)

// A session's live output is retained only in memory (seatterm's ring,
// bounded at RetainBytes), and reachable only by attaching live. A durable
// log, in the root alongside the journal, keeps the same bytes on disk, from
// creation, whether or not anything is ever attached, and survives this
// service ending: a restarted service can't resume the session, but it can
// still read what the last one captured.
//
// It is never the journal: the journal stays metadata only (who did what,
// when), and the log is exactly the program's own bytes, nothing else,
// carrying the same "not claimed free of secrets" caveat as a screen read.

// defaultSessionLogBytes bounds one session's durable log. Past it, further
// output isn't logged; the refusal is recorded once, in the journal, never
// inside the log itself, which stays exactly the program's bytes.
const defaultSessionLogBytes = 64 << 20

// maxLogChunk bounds one logs read: a huge log is paged, not dumped in one
// shot.
const maxLogChunk = 1 << 20

func logDir(root string) string { return filepath.Join(root, "logs") }

func logPath(root, id string) string { return filepath.Join(logDir(root), id+".log") }

// sessionLog is one session's durable log file, bounded at bound bytes: a
// field, not a shared constant, so a test can shrink one instance's bound
// without racing every other session's log goroutine that reads it.
type sessionLog struct {
	f     *os.File
	n     int64
	bound int64
	full  bool
}

// openSessionLog opens (or creates) id's log file in root, private and
// append-only.
func openSessionLog(root, id string, bound int64) (*sessionLog, error) {
	if err := os.MkdirAll(logDir(root), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(logPath(root, id), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
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
		return nil, errors.New("a session log must be a private regular file")
	}
	return &sessionLog{f: f, n: fi.Size(), bound: bound, full: fi.Size() >= bound}, nil
}

// append writes b, bounded at l.bound. It reports justFilled true exactly
// once, the moment the bound is reached, so the caller records it once.
func (l *sessionLog) append(b []byte) (justFilled bool) {
	if l.full || len(b) == 0 {
		return false
	}
	if room := l.bound - l.n; int64(len(b)) > room {
		b = b[:room]
	}
	if len(b) > 0 {
		n, _ := l.f.Write(b)
		l.n += int64(n)
		l.f.Sync()
	}
	if l.n >= l.bound {
		l.full = true
		return true
	}
	return false
}

func (l *sessionLog) close() { l.f.Close() }

// logSession attaches a durable viewer to t and drains its output into a log
// file, exactly the bytes any live client would see, from this point, for as
// long as the session runs: capturing it never depends on anything else
// being attached. It ends when the session's program exits, or at once if
// the log can't be opened (a durable log is a convenience; it never gates
// the session itself).
func (s *Server) logSession(t *seatterm.TermSession, op string) {
	l, err := openSessionLog(s.root, t.ID, s.logBound)
	if err != nil {
		return
	}
	c, snap, err := t.AttachHidden("log")
	if err != nil {
		l.close()
		return
	}
	bound := func() {
		s.j.write(Record{AuditRecord: seatterm.AuditRecord{Operation: op, Action: "log-bound", Phase: "outcome", Session: t.ID,
			Outcome: "truncated", Reason: fmt.Sprintf("the %d-byte log bound was reached; later output isn't logged", s.logBound)}})
	}
	if l.append(snap.Data) {
		bound()
	}
	go func() {
		defer l.close()
		defer c.Detach()
		for {
			select {
			case e, ok := <-c.Events():
				if !ok {
					return
				}
				if l.append(e.Data) {
					bound()
				}
			case <-c.Signals():
				if behind, _ := c.Gap(); behind {
					snap := c.Resnapshot()
					filled := l.append(snap.Data)
					s.j.write(Record{AuditRecord: seatterm.AuditRecord{Operation: op, Action: "log-gap", Phase: "outcome", Session: t.ID,
						Outcome: "resumed", Reason: "the log fell behind and resumed from a fresh cut; the bytes in between are lost"}})
					if filled {
						bound()
					}
				}
			}
		}
	}()
}

var sessionIDWord = regexp.MustCompile(`^[0-9a-f]{32}$`)

// logs is GET /v1/sessions/{name}/logs: a named session's durable log, by
// its current (or last known) session.
func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	t := s.lookup(w, r)
	if t == nil {
		return
	}
	s.serveLog(w, r, t.ID)
}

// logsByID is GET /v1/sessions/by-id/{id}/logs: a durable log by its exact
// session ID, reachable even once no name lists it any more (a restarted
// service forgets every name, never its logs on disk).
func (s *Server) logsByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !sessionIDWord.MatchString(id) {
		refuse(w, http.StatusBadRequest, KindUsage, "a session id is 32 lower-case hex digits")
		return
	}
	s.serveLog(w, r, id)
}

// serveLog answers a bounded, paged read of id's log: the raw bytes, never
// JSON-wrapped, with its size and this read's bounds in response headers.
func (s *Server) serveLog(w http.ResponseWriter, r *http.Request, id string) {
	from, limit := int64(0), int64(maxLogChunk)
	q := r.URL.Query()
	if v := q.Get("from"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			refuse(w, http.StatusBadRequest, KindUsage, "from must be a non-negative byte offset")
			return
		}
		from = n
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			refuse(w, http.StatusBadRequest, KindUsage, "limit must be a positive byte count")
			return
		}
		limit = min(n, maxLogChunk)
	}
	f, err := os.Open(logPath(s.root, id))
	if err != nil {
		refuse(w, http.StatusNotFound, KindNotFound, "no log for this session")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		refuse(w, http.StatusInternalServerError, KindInternal, err.Error())
		return
	}
	size := fi.Size()
	if from > size {
		from = size
	}
	n := min(limit, size-from)
	buf := make([]byte, n)
	if n > 0 {
		if _, err := f.ReadAt(buf, from); err != nil && err != io.EOF {
			refuse(w, http.StatusInternalServerError, KindInternal, err.Error())
			return
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Pomar-Log-Size", strconv.FormatInt(size, 10))
	w.Header().Set("X-Pomar-Log-From", strconv.FormatInt(from, 10))
	w.Header().Set("X-Pomar-Log-Truncated", strconv.FormatBool(from+n < size))
	w.WriteHeader(http.StatusOK)
	w.Write(buf)
}
