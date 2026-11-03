package agentenv

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// MailChannelOptions is supplied only by the owning no-model phase, after
// actual registration/claim. This constructor does not admit a profile, claim
// a row or bypass ordinary Host guards. Directory Root/Environment must exist.
type MailChannelOptions struct{ Root, Environment, Incarnation, Seat, Origin, Operation string }
type MailChannelBinding struct {
	Origin      string    `json:"origin"`
	Schema      string    `json:"schema"`
	SocketPath  string    `json:"socket_path"`
	Environment string    `json:"environment"`
	Incarnation string    `json:"incarnation"`
	Seat        string    `json:"seat"`
	Operation   string    `json:"operation"`
	OwnerUID    uint32    `json:"owner_uid"`
	Mode        uint32    `json:"mode"`
	Device      uint64    `json:"device"`
	Inode       uint64    `json:"inode"`
	Deadline    time.Time `json:"deadline"`
}

// MailOnlyChannel owns just one canonical 0600 Unix listener using the existing
// relay. It has no egress, Go proxy, agent control socket or VM functionality.
// Revoke is immediate; Close(ctx) additionally proves request/serve drain and
// records original closure. A timeout is inspect/retry-close, never a new open.
type MailOnlyChannel struct {
	life                          context.Context
	relay                         *mailRelay
	listener                      *net.UnixListener
	server                        *http.Server
	lock                          *os.File
	rootInfo, dirInfo, socketInfo os.FileInfo
	options                       MailChannelOptions
	binding                       MailChannelBinding
	mu                            sync.Mutex
	closing, drainSignaled        bool
	active                        int
	drained, serveDone, finished  chan struct{}
	revokeOnce                    sync.Once
	closeMu                       sync.Mutex
	closed                        bool
	closeErr, revokeErr, serveErr error
}

func mailHTTPServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
}
func privateMailDirectory(path string) (os.FileInfo, error) {
	real, e := filepath.EvalSymlinks(path)
	if e != nil || real != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("mail directory must already be canonical")
	}
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode().Perm()&0077 != 0 || int(sys.Uid) != os.Geteuid() {
		return nil, errors.New("mail directory needs private current-owner custody")
	}
	return st, nil
}
func (c *MailOnlyChannel) sameParents() error {
	root, e := privateMailDirectory(c.options.Root)
	if e != nil {
		return e
	}
	dir, e := privateMailDirectory(filepath.Dir(c.binding.SocketPath))
	if e != nil {
		return e
	}
	if !os.SameFile(root, c.rootInfo) || !os.SameFile(dir, c.dirInfo) {
		return errors.New("mail parent identity changed")
	}
	return nil
}
func (c *MailOnlyChannel) record(kind string, v any) error {
	if e := c.sameParents(); e != nil {
		return e
	}
	raw, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return writeEvidence(filepath.Join(filepath.Dir(c.binding.SocketPath), "mail-only-"+c.options.Incarnation+"."+kind+".json"), append(raw, '\n'))
}

// OpenMailOnlyChannel opens no upstream connection and requires a bounded owner
// lifetime. The fixed-seat handler retains all established route/header/body,
// budget and revocation rules. A guest can never supply these options.
func OpenMailOnlyChannel(ctx context.Context, o MailChannelOptions) (*MailOnlyChannel, error) {
	return openMailOnlyChannel(ctx, o, nil)
}
func openMailOnlyChannel(ctx context.Context, o MailChannelOptions, transport http.RoundTripper) (channel *MailOnlyChannel, err error) {
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || !deadline.After(time.Now()) || deadline.Sub(time.Now()) > 10*time.Minute {
		return nil, errors.New("mail-only channel needs original bounded owner context")
	}
	if !validID.MatchString(o.Environment) || !validID.MatchString(o.Incarnation) || !validID.MatchString(o.Operation) {
		return nil, errors.New("mail original identities required")
	}
	m, e := newMailRelay(o.Seat, o.Environment, o.Incarnation, o.Origin, transport)
	if e != nil {
		return nil, e
	}
	root, e := privateMailDirectory(o.Root)
	if e != nil {
		return nil, e
	}
	directory := filepath.Join(o.Root, o.Environment)
	dir, e := privateMailDirectory(directory)
	if e != nil {
		return nil, e
	}
	socket := filepath.Join(directory, "mail.sock")
	if len(socket) >= 104 {
		return nil, errors.New("canonical mail socket exceeds native Unix path bound")
	}
	c := &MailOnlyChannel{relay: m, life: ctx, rootInfo: root, dirInfo: dir, options: o, drained: make(chan struct{}), serveDone: make(chan struct{}), finished: make(chan struct{}), binding: MailChannelBinding{Schema: "pomar.mail-only-channel/v1", Origin: m.upstream.String(), SocketPath: socket, Environment: o.Environment, Incarnation: o.Incarnation, Seat: o.Seat, Operation: o.Operation, OwnerUID: uint32(os.Geteuid()), Mode: 0600, Deadline: deadline}}
	lock, e := os.OpenFile(filepath.Join(directory, "mail-only.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	c.lock = lock
	defer func() {
		if err != nil {
			m.Revoke()
			if c.listener != nil {
				c.listener.Close()
			}
			syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			lock.Close()
		}
	}()
	st, e := lock.Stat()
	if e != nil {
		return nil, e
	}
	ls, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || int(ls.Uid) != os.Geteuid() || ls.Nlink != 1 || st.Size() != 0 {
		return nil, errors.New("mail lock custody refused")
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return nil, errors.New("mail-only directory already owned")
	}
	if _, e = os.Lstat(socket); !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("mail socket path occupied or unknown; inspect original")
	}
	if e = c.record("intent", c.binding); e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		return nil, e
	}
	ln.SetUnlinkOnClose(false)
	c.listener = ln
	// A failed construction preserves its intent and any inert socket pathname.
	// Never remove a possibly replaced path on an uncertain partial open.
	if e = os.Chmod(socket, 0600); e != nil {
		return nil, e
	}
	st, e = os.Lstat(socket)
	if e != nil {
		return nil, e
	}
	ss, ok := st.Sys().(*syscall.Stat_t)
	if !ok || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 || int(ss.Uid) != os.Geteuid() {
		return nil, errors.New("actual mail listener custody refused")
	}
	c.socketInfo = st
	c.binding.Device = uint64(ss.Dev)
	c.binding.Inode = uint64(ss.Ino)
	if e = c.sameParents(); e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = c.record("ready", c.binding); e != nil {
		return nil, e
	}
	c.server = mailHTTPServer(http.HandlerFunc(c.handle))
	go func() {
		e := c.server.Serve(ln)
		c.mu.Lock()
		if e != nil && !errors.Is(e, http.ErrServerClosed) && !errors.Is(e, net.ErrClosed) {
			c.serveErr = e
		}
		c.mu.Unlock()
		close(c.serveDone)
		c.Revoke()
	}()
	go func() {
		select {
		case <-ctx.Done():
			c.Revoke()
		case <-c.finished:
		}
	}()
	return c, nil
}
func (c *MailOnlyChannel) signalDrainLocked() {
	if c.closing && c.active == 0 && !c.drainSignaled {
		close(c.drained)
		c.drainSignaled = true
	}
}
func (c *MailOnlyChannel) handle(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	if c.closing || c.life.Err() != nil {
		c.mu.Unlock()
		http.Error(w, "mail channel revoked", 503)
		return
	}
	c.active++
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.active--; c.signalDrainLocked(); c.mu.Unlock() }()
	requestCtx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(c.life, cancel)
	defer stop()
	defer cancel()
	c.relay.ServeHTTP(w, r.WithContext(requestCtx))
}
func (c *MailOnlyChannel) Revoke() {
	c.revokeOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		c.signalDrainLocked()
		c.mu.Unlock()
		c.relay.Revoke()
		e := c.server.Close()
		c.listener.Close()
		c.mu.Lock()
		c.revokeErr = e
		c.mu.Unlock()
	})
}

// Binding is a current owner observation, not an upstream authorization or
// guest attestation. The ready receipt alone is historical after revocation.
func (c *MailOnlyChannel) Binding() (MailChannelBinding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.life.Err() != nil || !c.binding.Deadline.After(time.Now()) {
		return MailChannelBinding{}, errors.New("mail-only channel is not live")
	}
	if e := c.sameParents(); e != nil {
		return MailChannelBinding{}, e
	}
	st, e := os.Lstat(c.binding.SocketPath)
	if e != nil || !os.SameFile(st, c.socketInfo) || st.Mode().Perm() != 0600 {
		return MailChannelBinding{}, errors.New("mail socket identity changed")
	}
	rc, e := c.listener.SyscallConn()
	if e != nil {
		return MailChannelBinding{}, e
	}
	// The listener is privately created by ListenUnix, never supplied as an
	// arbitrary descriptor. AF_UNIX SO_ACCEPTCONN is unsupported on the checked Darwin host;
	// inspect its still-open kernel binding instead of accepting a dead path.
	var addr syscall.Sockaddr
	var se error
	if e = rc.Control(func(fd uintptr) { addr, se = syscall.Getsockname(int(fd)) }); e != nil {
		return MailChannelBinding{}, e
	}
	unix, ok := addr.(*syscall.SockaddrUnix)
	if se != nil || !ok || unix.Name != c.binding.SocketPath {
		return MailChannelBinding{}, errors.New("owned mail listener kernel binding unavailable")
	}

	return c.binding, nil
}
func (c *MailOnlyChannel) Close(ctx context.Context) error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return c.closeErr
	}
	c.Revoke()
	for _, done := range []<-chan struct{}{c.serveDone, c.drained} {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.mu.Lock()
	e := errors.Join(c.revokeErr, c.serveErr)
	c.mu.Unlock()
	if pe := c.sameParents(); pe != nil {
		e = errors.Join(e, pe)
	} else {
		st, se := os.Lstat(c.binding.SocketPath)
		if se == nil {
			if !os.SameFile(st, c.socketInfo) {
				e = errors.Join(e, errors.New("mail socket replaced; unrelated path retained"))
			} else {
				e = errors.Join(e, os.Remove(c.binding.SocketPath))
			}
		} else if !errors.Is(se, os.ErrNotExist) {
			e = errors.Join(e, se)
		}
	}
	receipt := struct {
		Binding          MailChannelBinding `json:"binding"`
		TransportDrained bool               `json:"transport_drained"`
		Error            string             `json:"error,omitempty"`
	}{Binding: c.binding, TransportDrained: true}
	if e != nil {
		receipt.Error = e.Error()
	}
	e = errors.Join(e, c.record("closed", receipt))
	c.closed = true
	c.closeErr = e
	close(c.finished)
	e = errors.Join(e, syscall.Flock(int(c.lock.Fd()), syscall.LOCK_UN), c.lock.Close())
	c.closeErr = e
	return e
}
