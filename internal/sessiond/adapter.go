package sessiond

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/localclient"
	"github.com/zeroemployeeorg/pomar/internal/seatterm"
)

// StateEnv names, in a session's environment, the socket its adapter
// reports agent state on, when the session was made with a state channel.
const StateEnv = "POMAR_SESSION_STATE"

// maxStateLine bounds one line an adapter writes.
const maxStateLine = 4096

// AdapterReport is one line an adapter writes on the state channel: a
// state, an input it accepted, or both. An adapter is any program the
// session runs, or that its program starts; Pomar knows nothing of which
// agent it speaks for.
type AdapterReport struct {
	State    string `json:"state,omitempty"`    // running, waiting-input, permission or idle
	Detail   string `json:"detail,omitempty"`   // a short label, shown beside the state
	Accepted string `json:"accepted,omitempty"` // an input_id the program confirmed it accepted
}

// InputNotice is the line the service writes to the adapter once an input
// reached the program, so it can confirm it by input_id.
type InputNotice struct {
	InputID string `json:"input_id"`
	Bytes   int    `json:"bytes"`
	Mode    string `json:"mode"` // raw or when-ready
}

// adapter is one session's state channel: a private socket in the root,
// served for as long as the session runs. The latest connection is the
// adapter's; each line it writes is a report.
type adapter struct {
	path string
	ln   net.Listener
	t    *seatterm.TermSession
	j    *journal

	mu   sync.Mutex
	conn net.Conn
}

// statePath is a create's state socket: the same for every retry of one
// operation, so a retry asks for the same session.
func statePath(root, principal, op string) string {
	h := sha256.Sum256([]byte(principal + "\x00" + op))
	return filepath.Join(root, "a-"+hex.EncodeToString(h[:8])+".sock")
}

// listenState opens a state channel at path, admitting only this user.
func listenState(path string, j *journal) (*adapter, error) {
	if len(path) > maxSocketPath {
		return nil, errors.New("the state socket's path is too long for a Unix socket: choose a shorter root")
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, errors.New(path + " exists and isn't a socket")
		}
		os.Remove(path) // a stale channel: the root's lock is ours
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return &adapter{path: path, ln: ln, j: j}, nil
}

// start binds the channel to its session, then serves it: a connection made
// before, while the program starts, waits in the backlog. It closes when
// the session's program has exited.
func (a *adapter) start(t *seatterm.TermSession) {
	a.t = t
	go a.serve()
	go func() {
		<-t.Done()
		a.close()
	}()
}

func (a *adapter) close() {
	a.ln.Close()
	os.Remove(a.path)
	a.mu.Lock()
	if a.conn != nil {
		a.conn.Close()
	}
	a.mu.Unlock()
}

func (a *adapter) serve() {
	for {
		c, err := a.ln.Accept()
		if err != nil {
			return
		}
		if uid, err := localclient.PeerUID(c); err != nil || int(uid) != os.Geteuid() {
			a.j.write(Record{AuditRecord: seatterm.AuditRecord{Operation: newID(), Action: "adapter", Phase: "outcome", Session: a.t.ID, Outcome: "refused", Reason: "peer not this user"}})
			c.Close()
			continue
		}
		a.mu.Lock()
		if a.conn != nil {
			a.conn.Close() // the latest connection is the adapter's
		}
		a.conn = c
		a.mu.Unlock()
		go a.read(c)
	}
}

// read takes an adapter's reports, one JSON line each. A malformed or
// over-long line is answered with an error line and ends the connection.
func (a *adapter) read(c net.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 512), maxStateLine)
	for sc.Scan() {
		var r AdapterReport
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		err := dec.Decode(&r)
		if err == nil && r.State == "" && r.Accepted == "" {
			err = errors.New("a report carries a state, an accepted input_id, or both")
		}
		if err == nil {
			err = a.t.ReportAgent(r.State, r.Detail, r.Accepted)
		}
		if err != nil {
			a.reply(c, map[string]string{"error": err.Error()})
			return
		}
	}
	if sc.Err() != nil {
		a.reply(c, map[string]string{"error": "line too long"})
	}
}

func (a *adapter) reply(c net.Conn, v any) {
	b, _ := json.Marshal(v)
	c.SetWriteDeadline(time.Now().Add(time.Second))
	c.Write(append(b, '\n'))
}

// tell writes an input notice to the adapter, if one is connected. It
// never waits on an adapter that doesn't read.
func (a *adapter) tell(n InputNotice) {
	a.mu.Lock()
	c := a.conn
	a.mu.Unlock()
	if c != nil {
		a.reply(c, n)
	}
}
