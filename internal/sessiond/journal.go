package sessiond

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/seatterm"
)

// Record is one journal line: the session host's audit record, the service
// that wrote it, and, on a name record, the session's label. It is metadata
// only: never input, screens, commands or their arguments.
type Record struct {
	seatterm.AuditRecord
	Serve string `json:"serve"`
	Name  string `json:"name,omitempty"`
}

// journal appends records to the root's journal.jsonl, each synced before
// it counts: a grant whose intent can't be journaled is refused.
type journal struct {
	mu    sync.Mutex
	f     *os.File
	serve string
}

const journalName = "journal.jsonl"

// maxReconcile bounds how much of the journal a start reads back.
const maxReconcile = 64 << 20

func openJournal(root, serve string) (*journal, error) {
	f, err := os.OpenFile(filepath.Join(root, journalName), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, errors.New("the session journal must be a private regular file")
	}
	return &journal{f: f, serve: serve}, nil
}

func (j *journal) audit(r seatterm.AuditRecord) error {
	return j.write(Record{AuditRecord: r})
}

func (j *journal) write(r Record) error {
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	r.Serve = j.serve
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return j.f.Sync()
}

// Unrecovered is a session a previous service held, which this one can't
// reach. Whether its program still runs isn't known here.
type Unrecovered struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Serve string `json:"serve"`
}

// reconcile reads the journal back and returns the sessions an earlier
// service created and never saw end, each journaled as out of reach. It
// never claims one exited: a program can outlive the service that started it.
func (j *journal) reconcile(root string) ([]Unrecovered, error) {
	f, err := os.OpenFile(filepath.Join(root, journalName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	open := map[string]*Unrecovered{}
	var order []string
	sc := bufio.NewScanner(io.LimitReader(f, maxReconcile))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Session == "" {
			continue // a torn last line, say: it names nothing to reconcile
		}
		switch {
		case r.Action == "create" && r.Phase == "outcome" && r.Outcome == "ok":
			if open[r.Session] == nil {
				order = append(order, r.Session)
			}
			open[r.Session] = &Unrecovered{ID: r.Session, Serve: r.Serve}
		case r.Action == "name" && open[r.Session] != nil:
			open[r.Session].Name = r.Name
		case r.Action == "exit", r.Action == "reconcile":
			delete(open, r.Session)
		}
	}
	var out []Unrecovered
	for _, id := range order {
		u := open[id]
		if u == nil || u.Serve == j.serve {
			continue
		}
		if err := j.write(Record{AuditRecord: seatterm.AuditRecord{Operation: "reconcile-" + j.serve, Action: "reconcile", Phase: "outcome",
			Session: u.ID, Outcome: "out-of-reach", Reason: "held by an earlier service; not recovered, and not known to have exited"}, Name: u.Name}); err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, nil
}
