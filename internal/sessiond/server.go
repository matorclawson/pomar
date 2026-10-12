package sessiond

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/localclient"
	"github.com/zeroemployeeorg/pomar/internal/seatterm"
)

// Server is one session service, serving one root.
type Server struct {
	root        string
	serve       string // this service's ID, on every journal line it writes
	started     time.Time
	host        *seatterm.SessionHost
	j           *journal
	lock        *os.File
	unrecovered []Unrecovered

	mu       sync.Mutex
	named    map[string]*seatterm.TermSession // each name's latest generation
	reserved map[string]bool                  // names a create is starting
	creates  map[string]string                // principal and operation, to the name it created
	ops      map[string]*opResult             // send and stop results, by principal and operation
	opOrder  []string
}

// opResult is what one send or stop did. A retry with the same operation
// gets it back, and nothing is done twice.
type opResult struct {
	done    bool
	Session string `json:"session"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// Bounds on remembered operations and on ended sessions still listed.
const (
	maxOps      = 512
	maxExited   = 32
	sendConfirm = 10 * time.Second // how long a send waits for its write to reach the program
	// maxSocketPath is the longest Unix socket path every platform binds.
	maxSocketPath = 103
)

var nameWord = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func newID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Open prepares root, takes its lock, opens its journal, and reconciles
// what an earlier service held.
func Open(root string) (*Server, error) {
	if err := PrepareRoot(root); err != nil {
		return nil, err
	}
	root = canonical(root)
	lock, err := lockRoot(root)
	if err != nil {
		return nil, err
	}
	s := &Server{root: root, serve: newID(), started: time.Now().UTC(), lock: lock,
		named: map[string]*seatterm.TermSession{}, reserved: map[string]bool{}, creates: map[string]string{}, ops: map[string]*opResult{}}
	if s.j, err = openJournal(root, s.serve); err != nil {
		lock.Close()
		return nil, err
	}
	if err := s.j.write(Record{AuditRecord: seatterm.AuditRecord{Operation: "serve-" + s.serve, Action: "serve", Phase: "outcome", Outcome: "ok"}}); err != nil {
		s.Close()
		return nil, err
	}
	if s.unrecovered, err = s.j.reconcile(root); err != nil {
		s.Close()
		return nil, err
	}
	s.host = seatterm.NewSessionHost(s.j.audit)
	return s, nil
}

// Close releases the journal and the root's lock.
func (s *Server) Close() {
	if s.j != nil {
		s.j.f.Close()
	}
	s.lock.Close()
}

// Socket is the service's socket path.
func (s *Server) Socket() string { return filepath.Join(s.root, SocketName) }

// Serve listens on the root's socket until ctx ends, admitting only this
// user's processes, and calls ready (if set) once it listens. When it ends,
// it stops every session it holds, so each one's end is journaled rather
// than left to its terminal's hangup.
func (s *Server) Serve(ctx context.Context, ready func()) error {
	sock := s.Socket()
	if len(sock) > maxSocketPath {
		return fmt.Errorf("the socket path %s is %d bytes, beyond the %d a Unix socket allows: choose a shorter root", sock, len(sock), maxSocketPath)
	}
	if fi, err := os.Lstat(sock); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and isn't a socket", sock)
		}
		os.Remove(sock) // stale: the root's lock is ours
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		ln.Close()
		return err
	}
	if ready != nil {
		ready()
	}
	srv := &http.Server{Handler: s.mux(), ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, principalKey{}, c.(*ownerConn).principal)
		}}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	err = srv.Serve(&ownerListener{Listener: ln, s: s})
	os.Remove(sock)
	s.stopAll()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) stopAll() {
	for _, in := range s.host.List() {
		if in.Running {
			s.host.Terminate("serve-stop-"+s.serve, "service", in.ID)
		}
	}
}

// ownerListener admits only connections from this user's processes, by the
// uid the kernel recorded for the peer.
type ownerListener struct {
	net.Listener
	s *Server
}

type ownerConn struct {
	net.Conn
	principal string
}

type principalKey struct{}

func (l *ownerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := localclient.PeerUID(c)
		if err != nil || int(uid) != os.Geteuid() {
			reason := "peer uid " + strconv.Itoa(int(uid))
			if err != nil {
				reason = "peer unverified"
			}
			l.s.j.write(Record{AuditRecord: seatterm.AuditRecord{Operation: newID(), Action: "connect", Phase: "outcome", Outcome: "refused", Reason: reason}})
			c.Close()
			continue
		}
		return &ownerConn{Conn: c, principal: "uid:" + strconv.Itoa(int(uid))}, nil
	}
}

func principalOf(r *http.Request) string {
	p, _ := r.Context().Value(principalKey{}).(string)
	return p
}

// Error kinds, which the CLI maps to its fixed exit codes.
const (
	KindUsage      = "usage"
	KindNotFound   = "not_found"
	KindConflict   = "conflict"
	KindExited     = "exited"
	KindUncertain  = "uncertain"
	KindInternal   = "internal"
	KindInProgress = "in_progress"
)

// APIError is every refusal's body.
type APIError struct {
	Error string `json:"error"`
	Kind  string `json:"kind"`
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func refuse(w http.ResponseWriter, code int, kind, msg string) {
	reply(w, code, APIError{Error: msg, Kind: kind})
}

// hostError maps the session host's refusals to a status and kind.
func hostError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, seatterm.ErrOperationConflict), errors.Is(err, seatterm.ErrControlled), errors.Is(err, seatterm.ErrTooMany), errors.Is(err, seatterm.ErrInputBusy):
		refuse(w, http.StatusConflict, KindConflict, err.Error())
	case errors.Is(err, seatterm.ErrCreating):
		refuse(w, http.StatusConflict, KindInProgress, err.Error())
	case errors.Is(err, seatterm.ErrSessionExited):
		refuse(w, http.StatusConflict, KindExited, err.Error())
	case errors.Is(err, seatterm.ErrFenceUncertain), errors.Is(err, seatterm.ErrTerminateUncertain):
		refuse(w, http.StatusConflict, KindUncertain, err.Error())
	default:
		refuse(w, http.StatusInternalServerError, KindInternal, err.Error())
	}
}

// CreateRequest is POST /v1/sessions. Path is absolute, and Env is the
// program's whole environment: the service adds nothing.
type CreateRequest struct {
	Operation string   `json:"operation"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Path      string   `json:"path"`
	Args      []string `json:"args"`
	Env       []string `json:"env"`
	Dir       string   `json:"dir"`
	Cols      uint16   `json:"cols"`
	Rows      uint16   `json:"rows"`
}

// Created is a create's reply.
type Created struct {
	seatterm.SessionInfo
	Created bool `json:"created"` // false: this operation had already created it
}

// SendRequest is POST /v1/sessions/{name}/send.
type SendRequest struct {
	Operation string `json:"operation"`
	Text      string `json:"text"`
	Take      bool   `json:"take"`
}

// StopRequest is POST /v1/sessions/{name}/stop.
type StopRequest struct {
	Operation string `json:"operation"`
}

// Listing is GET /v1/sessions.
type Listing struct {
	Serve       string                 `json:"serve"`
	Started     time.Time              `json:"started"`
	Root        string                 `json:"root"`
	Sessions    []seatterm.SessionInfo `json:"sessions"`
	Unrecovered []Unrecovered          `json:"unrecovered"`
	Survives    string                 `json:"survives"`
}

func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		l := Listing{Serve: s.serve, Started: s.started, Root: s.root, Sessions: s.list(), Unrecovered: s.unrecovered,
			Survives: "clients and dropped connections; not a restart of this service, and not a reboot"}
		if l.Unrecovered == nil {
			l.Unrecovered = []Unrecovered{}
		}
		reply(w, http.StatusOK, l)
	})
	mux.HandleFunc("POST /v1/sessions", s.create)
	mux.HandleFunc("GET /v1/sessions/{name}", func(w http.ResponseWriter, r *http.Request) {
		if t := s.lookup(w, r); t != nil {
			reply(w, http.StatusOK, t.Info())
		}
	})
	mux.HandleFunc("GET /v1/sessions/{name}/screen", func(w http.ResponseWriter, r *http.Request) {
		if t := s.lookup(w, r); t != nil {
			reply(w, http.StatusOK, t.Screen())
		}
	})
	mux.HandleFunc("POST /v1/sessions/{name}/send", s.send)
	mux.HandleFunc("POST /v1/sessions/{name}/stop", s.stop)
	mux.HandleFunc("POST /v1/sessions/{name}/attach", s.attach)
	return mux
}

// list is every named session's latest generation, by name.
func (s *Server) list() []seatterm.SessionInfo {
	s.mu.Lock()
	all := make([]*seatterm.TermSession, 0, len(s.named))
	for _, t := range s.named {
		all = append(all, t)
	}
	s.mu.Unlock()
	out := make([]seatterm.SessionInfo, 0, len(all))
	for _, t := range all {
		out = append(out, t.Info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Server) lookup(w http.ResponseWriter, r *http.Request) *seatterm.TermSession {
	name := r.PathValue("name")
	s.mu.Lock()
	t := s.named[name]
	s.mu.Unlock()
	if t == nil {
		refuse(w, http.StatusNotFound, KindNotFound, "no session named "+name)
	}
	return t
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		refuse(w, http.StatusBadRequest, KindUsage, "malformed request: "+err.Error())
		return false
	}
	return true
}

// create starts a named session once per operation. A name already running
// is refused, never replaced; a name whose program has ended takes a new
// generation.
func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var req CreateRequest
	if !decode(w, r, &req) {
		return
	}
	p := principalOf(r)
	if req.Operation == "" || !nameWord.MatchString(req.Name) {
		refuse(w, http.StatusBadRequest, KindUsage, "a session needs an operation ID and a name: a lower-case word of up to 32 letters, digits and dashes")
		return
	}
	if req.Kind == "" {
		req.Kind = "program"
	}
	spec := seatterm.SessionSpec{Name: req.Name, Kind: req.Kind, Cols: req.Cols, Rows: req.Rows,
		Command: seatterm.Command{Path: req.Path, Args: req.Args, Env: req.Env, Dir: req.Dir, UID: -1, GID: -1}}
	key := p + "\x00" + req.Operation
	s.mu.Lock()
	name, retry := s.creates[key]
	if retry && name != req.Name {
		s.mu.Unlock()
		refuse(w, http.StatusConflict, KindConflict, "this operation ID already created a session with a different spec")
		return
	} else if !retry {
		if s.reserved[req.Name] || (s.named[req.Name] != nil && s.named[req.Name].Info().Running) {
			s.mu.Unlock()
			refuse(w, http.StatusConflict, KindConflict, "a session named "+req.Name+" is running; stop it, or choose another name")
			return
		}
		s.reserved[req.Name] = true
		s.creates[key] = req.Name
		defer func() {
			s.mu.Lock()
			delete(s.reserved, req.Name)
			s.mu.Unlock()
		}()
	}
	s.mu.Unlock()
	t, created, err := s.host.Create(req.Operation, p, spec)
	if err != nil {
		if !retry {
			s.mu.Lock()
			delete(s.creates, key) // this request reserved the name, and nothing was made
			s.mu.Unlock()
		}
		if errors.Is(err, seatterm.ErrOperationConflict) || errors.Is(err, seatterm.ErrCreating) || errors.Is(err, seatterm.ErrTooMany) || errors.Is(err, seatterm.ErrAudit) {
			hostError(w, err)
			return
		}
		refuse(w, http.StatusBadRequest, KindUsage, err.Error())
		return
	}
	if created {
		s.j.write(Record{AuditRecord: seatterm.AuditRecord{Operation: req.Operation, Action: "name", Phase: "outcome", Principal: p, Session: t.ID, Outcome: "ok"}, Name: req.Name})
		s.mu.Lock()
		s.named[req.Name] = t
		s.pruneExitedLocked()
		s.mu.Unlock()
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	reply(w, code, Created{SessionInfo: t.Info(), Created: created})
}

// pruneExitedLocked bounds the ended sessions still listed.
func (s *Server) pruneExitedLocked() {
	var ended []string
	for name, t := range s.named {
		if !t.Info().Running {
			ended = append(ended, name)
		}
	}
	sort.Strings(ended)
	for len(ended) > maxExited {
		delete(s.named, ended[0])
		ended = ended[1:]
	}
}

// begin claims an operation, or returns what it already did: a retry never
// acts twice.
func (s *Server) begin(kind, p, op string) (*opResult, bool) {
	key := kind + "\x00" + p + "\x00" + op
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.ops[key]; ok {
		return r, false
	}
	r := &opResult{}
	s.ops[key] = r
	s.opOrder = append(s.opOrder, key)
	for len(s.opOrder) > maxOps {
		if old := s.ops[s.opOrder[0]]; old != nil && !old.done {
			break // an operation still running is never forgotten
		}
		delete(s.ops, s.opOrder[0])
		s.opOrder = s.opOrder[1:]
	}
	return r, true
}

// drop forgets an operation that did nothing, so a retry decides afresh.
func (s *Server) drop(r *opResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, k := range s.opOrder {
		if s.ops[k] == r {
			delete(s.ops, k)
			s.opOrder = append(s.opOrder[:i], s.opOrder[i+1:]...)
			return
		}
	}
}

func (s *Server) finish(r *opResult, session, outcome, detail string) opResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Session, r.Outcome, r.Detail, r.done = session, outcome, detail, true
	return *r
}

func (s *Server) recorded(w http.ResponseWriter, r *opResult) {
	s.mu.Lock()
	done, out := r.done, *r
	s.mu.Unlock()
	if !done {
		refuse(w, http.StatusConflict, KindInProgress, "this operation is still running; ask again with the same ID")
		return
	}
	reply(w, http.StatusOK, out)
}

// send writes text to a session's program as its controller for the
// moment: it takes control only when nobody holds it (or, with take, from
// whoever does), waits for the write to reach the program, and gives
// control back.
func (s *Server) send(w http.ResponseWriter, r *http.Request) {
	var req SendRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Operation == "" || req.Text == "" {
		refuse(w, http.StatusBadRequest, KindUsage, "a send needs an operation ID and its text")
		return
	}
	p := principalOf(r)
	res, fresh := s.begin("send", p, req.Operation)
	if !fresh {
		s.recorded(w, res)
		return
	}
	t := s.lookup(w, r)
	if t == nil {
		s.drop(res)
		return
	}
	if !t.Info().Running {
		s.drop(res)
		hostError(w, seatterm.ErrSessionExited)
		return
	}
	c, _, err := t.Attach(p)
	if err != nil {
		s.drop(res)
		hostError(w, err)
		return
	}
	defer c.Detach()
	if _, err := c.Control(req.Take, "send "+req.Operation); err != nil {
		s.drop(res)
		hostError(w, err)
		return
	}
	data, queued := []byte(req.Text), 0
	for len(data) > 0 {
		n := min(len(data), seatterm.MaxData)
		if err := c.Input(data[:n]); err != nil {
			out := s.finish(res, t.ID, "partial", fmt.Sprintf("%d of %d bytes queued: %v", len(req.Text)-len(data), len(req.Text), err))
			reply(w, http.StatusConflict, out)
			return
		}
		data, queued = data[n:], queued+1
	}
	deadline := time.Now().Add(sendConfirm)
	for {
		o := c.Outcomes()
		if o.Written+o.Partial+o.Failed+o.Refused >= queued {
			if o.Written == queued {
				reply(w, http.StatusOK, s.finish(res, t.ID, "written", ""))
			} else {
				reply(w, http.StatusConflict, s.finish(res, t.ID, "partial", fmt.Sprintf("%+v", o)))
			}
			return
		}
		if time.Now().After(deadline) {
			reply(w, http.StatusConflict, s.finish(res, t.ID, "uncertain", "the program didn't read the input in time; what it got is unknown, and nothing is resent"))
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stop ends a session's program. It acts on the generation the name had
// when the operation began, never on one that took the name since.
func (s *Server) stop(w http.ResponseWriter, r *http.Request) {
	var req StopRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Operation == "" {
		refuse(w, http.StatusBadRequest, KindUsage, "a stop needs an operation ID")
		return
	}
	p := principalOf(r)
	res, fresh := s.begin("stop", p, req.Operation)
	if !fresh {
		s.recorded(w, res)
		return
	}
	t := s.lookup(w, r)
	if t == nil {
		s.drop(res)
		return
	}
	if !t.Info().Running {
		reply(w, http.StatusOK, s.finish(res, t.ID, "already-exited", ""))
		return
	}
	if err := s.host.Terminate(req.Operation, p, t.ID); err != nil {
		if !t.Info().Running {
			reply(w, http.StatusOK, s.finish(res, t.ID, "already-exited", ""))
			return
		}
		s.finish(res, t.ID, "uncertain", err.Error())
		hostError(w, err)
		return
	}
	reply(w, http.StatusOK, s.finish(res, t.ID, "stopped", ""))
}
