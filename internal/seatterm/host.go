package seatterm

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"
)

// SessionHost holds a seat's terminal sessions in its guest, in place of a
// terminal multiplexer (POMAR-CC SOW 27, made agent-agnostic by SOW 28):
// each session is one program on a PTY the host owns, so the program
// outlives every client. Any number of clients, up to a bound, view a
// session; at most one controls it. Only the controller's input and window
// size reach the PTY, and each is fenced at the write itself by the
// controller's grant epoch, so a revoked controller's queued input never
// lands. The host knows nothing about which program a session runs.
type SessionHost struct {
	mu       sync.Mutex
	sessions map[string]*TermSession
	byOp     map[string]string // creation operation ID -> session ID
	audit    func(AuditRecord) error
	now      func() time.Time
}

// Bounds on a host, its sessions and their clients.
const (
	MaxSessions = 8
	MaxViewers  = 8       // per session, the controller included
	RetainBytes = 1 << 20 // a session's retained output
	viewerQueue = 256     // output chunks queued for one client
	inputQueue  = 64      // input and resize writes queued for the PTY
	fenceBound  = 3 * time.Second
)

// Errors a client is refused with.
var (
	ErrNotController  = errors.New("this client doesn't hold control of the session")
	ErrControlled     = errors.New("another client controls the session; take control explicitly")
	ErrInputBusy      = errors.New("the session's input queue is full; nothing was queued")
	ErrSessionExited  = errors.New("the session's program has exited")
	ErrTooMany        = errors.New("the bound on sessions or clients is reached")
	ErrFenceUncertain = errors.New("the previous controller's write couldn't be confirmed fenced; control was not granted")
	ErrAudit          = errors.New("the audit record couldn't be written; nothing was granted")
)

// AuditRecord is the metadata the host journals for every grant, revocation
// and session change: never keystrokes, screen contents or arguments.
type AuditRecord struct {
	At        time.Time `json:"at"`
	Operation string    `json:"operation_id"`
	Action    string    `json:"action"` // create, attach, detach, grant, take, release, revoke, exit
	Phase     string    `json:"phase"`  // intent or outcome
	Principal string    `json:"principal"`
	Session   string    `json:"session"`
	Epoch     uint64    `json:"epoch,omitempty"`
	Outcome   string    `json:"outcome,omitempty"` // ok, refused, uncertain, error
	Reason    string    `json:"reason,omitempty"`
}

// SessionSpec is what a new session runs. Name is a display label, never
// authority; the session's ID is its identity.
type SessionSpec struct {
	Name       string
	Kind       string // agent, shell, or another lower-case word
	Command    Command
	Cols, Rows uint16
}

var sessionWord = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// NewSessionHost returns a host that journals through audit, which must be
// durable: a grant is refused when its intent can't be recorded.
func NewSessionHost(audit func(AuditRecord) error) *SessionHost {
	return &SessionHost{sessions: map[string]*TermSession{}, byOp: map[string]string{}, audit: audit, now: time.Now}
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func (h *SessionHost) record(r AuditRecord) error {
	r.At = h.now().UTC()
	if h.audit == nil {
		return errors.New("no audit journal")
	}
	return h.audit(r)
}

// Create starts a session, once per operation ID: a retry with the same ID
// returns the session it made, and never starts a second program.
func (h *SessionHost) Create(operation, principal string, spec SessionSpec) (*TermSession, bool, error) {
	if operation == "" || !sessionWord.MatchString(spec.Name) || !sessionWord.MatchString(spec.Kind) || spec.Command.Path == "" ||
		spec.Cols < 1 || spec.Cols > MaxCols || spec.Rows < 1 || spec.Rows > MaxRows {
		return nil, false, errors.New("a session needs an operation ID, a name, a kind, its command and a bounded window size")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if id, ok := h.byOp[operation]; ok {
		return h.sessions[id], false, nil
	}
	if len(h.sessions) >= MaxSessions {
		return nil, false, ErrTooMany
	}
	id := newID()
	if err := h.record(AuditRecord{Operation: operation, Action: "create", Phase: "intent", Principal: principal, Session: id, Reason: spec.Kind}); err != nil {
		return nil, false, ErrAudit
	}
	s, err := startSession(h, id, spec)
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	h.record(AuditRecord{Operation: operation, Action: "create", Phase: "outcome", Principal: principal, Session: id, Outcome: outcome})
	if err != nil {
		return nil, false, err
	}
	h.sessions[id], h.byOp[operation] = s, id
	return s, true, nil
}

// Session returns a session by its ID.
func (h *SessionHost) Session(id string) (*TermSession, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[id]
	return s, ok
}

// SessionInfo is a session as listed.
type SessionInfo struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Running    bool     `json:"running"`
	ExitCode   *int     `json:"exit_code,omitempty"`
	LastOutput string   `json:"last_output,omitempty"`
	Cols       uint16   `json:"cols"`
	Rows       uint16   `json:"rows"`
	Controller string   `json:"controller,omitempty"`
	Epoch      uint64   `json:"epoch"`
	Viewers    []string `json:"viewers"`
}

// List returns every session, ordered by name then ID.
func (h *SessionHost) List() []SessionInfo {
	h.mu.Lock()
	all := make([]*TermSession, 0, len(h.sessions))
	for _, s := range h.sessions {
		all = append(all, s)
	}
	h.mu.Unlock()
	out := make([]SessionInfo, 0, len(all))
	for _, s := range all {
		out = append(out, s.Info())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// TermSession is one program on a PTY the host owns.
type TermSession struct {
	ID, Name, Kind string
	host           *SessionHost
	master         *os.File
	tty            string
	cmd            *exec.Cmd
	writes         chan pendingWrite
	done           chan struct{} // closed once the program has exited and its output is drained

	mu         sync.Mutex
	fence      *sync.Cond // signalled when an in-flight write ends
	log        []byte     // retained output, the bytes [base, end)
	base, end  uint64
	exited     bool
	exitCode   int
	lastOutput time.Time
	cols, rows uint16
	viewers    map[*Client]struct{}
	controller *Client
	epoch      uint64
	inflight   uint64 // the epoch of the write now at the PTY, or 0
}

type pendingWrite struct {
	epoch      uint64
	data       []byte
	cols, rows uint16 // a resize when data is nil
}

func startSession(h *SessionHost, id string, spec SessionSpec) (*TermSession, error) {
	master, tty, err := openPTY()
	if err != nil {
		return nil, err
	}
	slave, err := os.OpenFile(tty, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err == nil {
		if err = setSize(slave, spec.Cols, spec.Rows); err != nil {
			slave.Close()
		}
	}
	if err != nil {
		master.Close()
		return nil, err
	}
	c := spec.Command
	cmd := exec.Command(c.Path, c.Args...)
	cmd.Env, cmd.Dir = c.Env, c.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if c.UID >= 0 && c.GID >= 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(c.UID), Gid: uint32(c.GID)}
	}
	err = cmd.Start()
	slave.Close()
	if err != nil {
		master.Close()
		return nil, err
	}
	s := &TermSession{ID: id, Name: spec.Name, Kind: spec.Kind, host: h, master: master, tty: tty, cmd: cmd,
		writes: make(chan pendingWrite, inputQueue), done: make(chan struct{}), cols: spec.Cols, rows: spec.Rows,
		viewers: map[*Client]struct{}{}}
	s.fence = sync.NewCond(&s.mu)
	go s.pump()
	go s.writer()
	return s, nil
}

// pump drains the PTY always, whatever the clients do: a terminal whose
// output nobody reads keeps its last process from exiting.
func (s *TermSession) pump() {
	buf := make([]byte, MaxData)
	for {
		n, err := s.master.Read(buf)
		if n > 0 {
			s.output(buf[:n])
		}
		if err != nil {
			break // EIO once the terminal side has no process left
		}
	}
	waitErr := s.cmd.Wait()
	code := 0
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) {
		code = exit.ExitCode()
	} else if waitErr != nil {
		code = -1
	}
	s.mu.Lock()
	s.exited, s.exitCode = true, code
	s.epoch++ // nothing more is written to a terminal without a program
	for c := range s.viewers {
		c.notify(Event{Kind: EventState})
	}
	s.mu.Unlock()
	close(s.writes)
	s.master.Close()
	close(s.done)
	s.host.record(AuditRecord{Operation: newID(), Action: "exit", Phase: "outcome", Session: s.ID, Outcome: "ok", Reason: fmt.Sprintf("exit %d", code)})
}

// output retains b and hands it to every client in order. A client whose
// queue is full is marked behind and gets nothing more until it asks for a
// new snapshot: no byte is silently lost and nothing waits on a client.
func (s *TermSession) output(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	off := s.end
	s.log = append(s.log, b...)
	s.end += uint64(len(b))
	if over := len(s.log) - RetainBytes; over > 0 {
		s.log = append([]byte(nil), s.log[over:]...)
		s.base += uint64(over)
	}
	s.lastOutput = s.host.now()
	for c := range s.viewers {
		if c.behind {
			continue
		}
		select {
		case c.events <- Event{Kind: EventOutput, Offset: off, Data: append([]byte(nil), b...)}:
		default:
			c.behind = true
			c.notify(Event{Kind: EventGap, Offset: off})
		}
	}
}

// writer is the only place input and window sizes reach the PTY. Each write
// is checked against the current grant epoch at the moment it is made, and
// marked in flight, so a fence can wait for it.
func (s *TermSession) writer() {
	for w := range s.writes {
		s.mu.Lock()
		ok := w.epoch == s.epoch && s.controller != nil && !s.exited
		if ok {
			s.inflight = w.epoch
			// A write waits for the program to read, however long: input
			// is never dropped on a timer. Only a fence cuts it short, and
			// it sets its deadline under this same lock, so the cut can't
			// be lost to this reset.
			s.master.SetWriteDeadline(time.Time{})
		}
		s.mu.Unlock()
		if !ok {
			continue // a revoked or stale controller's write never lands
		}
		if w.data == nil {
			resize(s.tty, w.cols, w.rows)
			s.mu.Lock()
			s.cols, s.rows = w.cols, w.rows
			for c := range s.viewers {
				c.notify(Event{Kind: EventState})
			}
			s.mu.Unlock()
		} else {
			s.master.Write(w.data)
		}
		s.mu.Lock()
		s.inflight = 0
		s.fence.Broadcast()
		s.mu.Unlock()
	}
}

// Info is the session's current state.
func (s *TermSession) Info() SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := SessionInfo{ID: s.ID, Name: s.Name, Kind: s.Kind, Running: !s.exited, Cols: s.cols, Rows: s.rows, Epoch: s.epoch, Viewers: []string{}}
	if s.exited {
		code := s.exitCode
		in.ExitCode = &code
	}
	if !s.lastOutput.IsZero() {
		in.LastOutput = s.lastOutput.UTC().Format(time.RFC3339Nano)
	}
	if s.controller != nil {
		in.Controller = s.controller.Principal
	}
	for c := range s.viewers {
		in.Viewers = append(in.Viewers, c.Principal)
	}
	sort.Strings(in.Viewers)
	return in
}

// Done is closed once the session's program has exited.
func (s *TermSession) Done() <-chan struct{} { return s.done }

// Snapshot is the retained output as one atomic cut: the bytes [From, To),
// after which a client's output events start exactly at To. Complete says
// the retained bytes reach back to the session's start; when they don't, a
// replay alone may not reproduce the screen, and a client must say so
// rather than claim an exact resume.
type Snapshot struct {
	Kind       string `json:"kind"` // "replay": the retained bytes, to be fed through a terminal
	From       uint64 `json:"from"`
	To         uint64 `json:"to"`
	Complete   bool   `json:"complete"`
	Cols       uint16 `json:"cols"`
	Rows       uint16 `json:"rows"`
	Data       []byte `json:"-"`
	Generation string `json:"session"`
}

func (s *TermSession) snapshotLocked() Snapshot {
	return Snapshot{Kind: "replay", From: s.base, To: s.end, Complete: s.base == 0, Cols: s.cols, Rows: s.rows,
		Data: append([]byte(nil), s.log...), Generation: s.ID}
}

// Attach adds a viewing client and returns it with its snapshot. Viewing
// grants nothing: no input, no resize.
func (s *TermSession) Attach(principal string) (*Client, Snapshot, error) {
	op := newID()
	if err := s.host.record(AuditRecord{Operation: op, Action: "attach", Phase: "intent", Principal: principal, Session: s.ID}); err != nil {
		return nil, Snapshot{}, ErrAudit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.viewers) >= MaxViewers {
		s.host.record(AuditRecord{Operation: op, Action: "attach", Phase: "outcome", Principal: principal, Session: s.ID, Outcome: "refused", Reason: "viewer bound"})
		return nil, Snapshot{}, ErrTooMany
	}
	c := &Client{Principal: principal, s: s, events: make(chan Event, viewerQueue), signal: make(chan struct{}, 1)}
	s.viewers[c] = struct{}{}
	s.host.record(AuditRecord{Operation: op, Action: "attach", Phase: "outcome", Principal: principal, Session: s.ID, Outcome: "ok"})
	return c, s.snapshotLocked(), nil
}

// EventKind names a client event.
type EventKind int

const (
	EventOutput EventKind = iota // Data at Offset
	EventGap                     // the client fell behind at Offset; ask for a new snapshot
	EventState                   // the session's state, control or size changed; read Info
)

// Event is one thing a client is told, in order.
type Event struct {
	Kind   EventKind
	Offset uint64
	Data   []byte
}

// Client is one viewer of a session, and possibly its controller.
type Client struct {
	Principal string
	s         *TermSession
	events    chan Event
	signal    chan struct{} // gap and state notices, which never queue behind output
	behind    bool
	gone      bool
	epoch     uint64 // the grant epoch while this client controls
}

// Events is the client's ordered output; Signals says a gap or a state
// change is waiting (read Info, or Resnapshot after a gap).
func (c *Client) Events() <-chan Event     { return c.events }
func (c *Client) Signals() <-chan struct{} { return c.signal }

// Behind reports whether the client missed output and needs a new snapshot.
func (c *Client) Behind() bool {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	return c.behind
}

func (c *Client) notify(Event) {
	select {
	case c.signal <- struct{}{}:
	default:
	}
}

// Resnapshot gives a client that fell behind a fresh cut, and resumes its
// output after it. Output queued before the cut is discarded, never mixed.
func (c *Client) Resnapshot() Snapshot {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
drain:
	for {
		select {
		case <-c.events:
		default:
			break drain
		}
	}
	c.behind = false
	return s.snapshotLocked()
}

// Control asks for control. With take false it is granted only when nobody
// controls the session. With take true the current controller is revoked
// first, and control is granted only once that controller's write in
// flight, if any, is confirmed ended; its queued writes never land. The
// grant's intent is journaled before anything changes.
func (c *Client) Control(take bool, reason string) (uint64, error) {
	s := c.s
	action := "grant"
	if take {
		action = "take"
	}
	op := newID()
	if err := s.host.record(AuditRecord{Operation: op, Action: action, Phase: "intent", Principal: c.Principal, Session: s.ID, Reason: reason}); err != nil {
		return 0, ErrAudit
	}
	outcome := func(result string, epoch uint64, why string) {
		s.host.record(AuditRecord{Operation: op, Action: action, Phase: "outcome", Principal: c.Principal, Session: s.ID, Epoch: epoch, Outcome: result, Reason: why})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case c.gone:
		outcome("refused", 0, "detached")
		return 0, ErrNotController
	case s.exited:
		outcome("refused", 0, "exited")
		return 0, ErrSessionExited
	case s.controller == c:
		outcome("ok", s.epoch, "already controls")
		return s.epoch, nil
	case s.controller != nil && !take:
		outcome("refused", 0, "controlled")
		return 0, ErrControlled
	}
	old := s.epoch
	s.epoch++ // from here, nothing queued under the old epoch reaches the PTY
	if prev := s.controller; prev != nil {
		prev.epoch = 0
		s.controller = nil
		prev.notify(Event{Kind: EventState})
	}
	if !s.waitFenceLocked(old) {
		outcome("uncertain", 0, "previous write not confirmed ended")
		return 0, ErrFenceUncertain
	}
	// The wait released the lock: anyone who took control meanwhile, or an
	// exit, wins, and this request is refused rather than overriding it.
	if s.controller != nil || s.exited || c.gone {
		outcome("refused", 0, "changed while fencing")
		return 0, ErrControlled
	}
	s.epoch++
	s.controller, c.epoch = c, s.epoch
	for v := range s.viewers {
		v.notify(Event{Kind: EventState})
	}
	outcome("ok", s.epoch, "")
	return s.epoch, nil
}

// waitFenceLocked waits, bounded, for a write made under epoch old to end,
// cutting it short through the PTY's write deadline.
func (s *TermSession) waitFenceLocked(old uint64) bool {
	if s.inflight == 0 || s.inflight > old {
		return true
	}
	s.master.SetWriteDeadline(time.Now())
	deadline := time.Now().Add(fenceBound)
	timer := time.AfterFunc(fenceBound, func() {
		s.mu.Lock()
		s.fence.Broadcast()
		s.mu.Unlock()
	})
	defer timer.Stop()
	for s.inflight != 0 && s.inflight <= old {
		if !time.Now().Before(deadline) {
			return false
		}
		s.fence.Wait()
	}
	return true
}

// Input queues keys for the PTY under the client's grant. It is refused,
// never queued, for a client that doesn't control the session, and when the
// queue is full.
func (c *Client) Input(b []byte) error {
	if len(b) == 0 || len(b) > MaxData {
		return errors.New("input is 1 byte to one frame")
	}
	return c.queue(pendingWrite{data: append([]byte(nil), b...)})
}

// Resize sets the session's window size, under the client's grant.
func (c *Client) Resize(cols, rows uint16) error {
	if cols < 1 || cols > MaxCols || rows < 1 || rows > MaxRows {
		return fmt.Errorf("window size %dx%d is out of bounds", cols, rows)
	}
	return c.queue(pendingWrite{cols: cols, rows: rows})
}

func (c *Client) queue(w pendingWrite) error {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controller != c || c.epoch != s.epoch {
		return ErrNotController
	}
	if s.exited {
		return ErrSessionExited
	}
	w.epoch = c.epoch
	select {
	case s.writes <- w:
		return nil
	default:
		return ErrInputBusy
	}
}

// Release gives up control; the session keeps running.
func (c *Client) Release() {
	s := c.s
	s.mu.Lock()
	held := s.controller == c
	if held {
		s.epoch++
		s.controller, c.epoch = nil, 0
		for v := range s.viewers {
			v.notify(Event{Kind: EventState})
		}
	}
	s.mu.Unlock()
	if held {
		// A revocation is never held up by the journal: it is recorded when it can be.
		s.host.record(AuditRecord{Operation: newID(), Action: "release", Phase: "outcome", Principal: c.Principal, Session: s.ID, Outcome: "ok"})
	}
}

// Detach removes the client, releasing any control it holds. It never stops
// the session's program.
func (c *Client) Detach() {
	c.Release()
	s := c.s
	s.mu.Lock()
	if !c.gone {
		c.gone = true
		delete(s.viewers, c)
	}
	s.mu.Unlock()
	s.host.record(AuditRecord{Operation: newID(), Action: "detach", Phase: "outcome", Principal: c.Principal, Session: s.ID, Outcome: "ok"})
}
