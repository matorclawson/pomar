package agentenv

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func mailOnlyFixture(t *testing.T) (context.Context, MailChannelOptions) {
	t.Helper()
	root, e := os.MkdirTemp(os.TempDir(), "mc-")
	if e != nil {
		t.Fatal(e)
	}
	real, e := filepath.EvalSymlinks(root)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(real) })
	if e = os.Mkdir(filepath.Join(real, "e"), 0700); e != nil {
		t.Fatal(e)
	}
	o := MailChannelOptions{Root: real, Environment: "e", Incarnation: "inc", Operation: "op", Seat: "disposable", Origin: "http://mail.example:7743"}
	if len(filepath.Join(real, "e", "mail.sock")) >= 104 {
		t.Fatal("fixture needs approved short private TMPDIR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx, o
}
func closeMailOnly(t *testing.T, c *MailOnlyChannel) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e := c.Close(ctx); e != nil {
		t.Error(e)
	}
}
func mailOnlyClient(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}, Timeout: 10 * time.Second}
}
func TestMailOnlyChannelCreatesOnlyBoundMailAndPreservesRelayPolicy(t *testing.T) {
	ctx, o := mailOnlyFixture(t)
	var calls atomic.Int32
	c, e := openMailOnlyChannel(ctx, o, mailTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Header.Get("X-Zmail-Instance") != o.Seat || len(r.Header.Values("X-Zmail-Instance")) != 1 || r.URL.Host != "mail.example:7743" || r.Header.Get("Authorization") != "" {
			t.Error("existing fixed policy changed")
		}
		return mailResponse(200, `{"exit":0,"output":"{}"}`), nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	defer closeMailOnly(t, c)
	b, e := c.Binding()
	if e != nil {
		t.Fatal(e)
	}
	st, e := os.Lstat(b.SocketPath)
	if e != nil {
		t.Fatal(e)
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 || b.Seat != o.Seat || b.Environment != o.Environment || b.Incarnation != o.Incarnation || b.Operation != o.Operation || b.OwnerUID != uint32(os.Geteuid()) || b.Inode == 0 || calls.Load() != 0 {
		t.Fatal("not a real bounded owner mail-only binding")
	}
	for _, n := range []string{"egress.sock", "go.sock", "gocache", "agent.sock", "environment.json"} {
		if _, e := os.Lstat(filepath.Join(o.Root, o.Environment, n)); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("ordinary host channel/state created", n, e)
		}
	}
	client := mailOnlyClient(b.SocketPath)
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "http://local/v1/whoami", nil)
	req.Header.Set("Authorization", "guest-secret")
	r, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || calls.Load() != 1 {
		t.Fatal("positive fixed relay failed")
	}
	req, _ = http.NewRequest("GET", "http://local/v1/whoami", nil)
	req.Header.Set("X-Zmail-Instance", "foreign")
	r, e = client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 403 || calls.Load() != 1 {
		t.Fatal("foreign header reached upstream")
	}
	closeMailOnly(t, c)
	if _, e = c.Binding(); e == nil {
		t.Fatal("revoked ready receipt treated as live")
	}
	if _, e = os.Lstat(b.SocketPath); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("owned socket not removed")
	}
	raw, e := os.ReadFile(filepath.Join(o.Root, o.Environment, "mail-only-inc.closed.json"))
	if e != nil {
		t.Fatal(e)
	}
	var receipt struct {
		TransportDrained bool `json:"transport_drained"`
	}
	if json.Unmarshal(raw, &receipt) != nil || !receipt.TransportDrained {
		t.Fatal("positive drain receipt absent")
	}
	if _, e = openMailOnlyChannel(ctx, o, nil); e == nil {
		t.Fatal("reused original reopened")
	}
}
func TestMailOnlyChannelRefusesOccupiedDeadAndRedirectedPaths(t *testing.T) {
	for _, kind := range []string{"file", "live", "dead", "parent-symlink", "public-directory"} {
		t.Run(kind, func(t *testing.T) {
			ctx, o := mailOnlyFixture(t)
			dir := filepath.Join(o.Root, o.Environment)
			path := filepath.Join(dir, "mail.sock")
			switch kind {
			case "file":
				if e := os.WriteFile(path, []byte("do not replace"), 0600); e != nil {
					t.Fatal(e)
				}
			case "live", "dead":
				ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if e != nil {
					t.Fatal(e)
				}
				ln.SetUnlinkOnClose(false)
				defer ln.Close()
				if kind == "dead" {
					ln.Close()
				}
			case "parent-symlink":
				if e := os.Rename(dir, dir+"-real"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(dir+"-real", dir); e != nil {
					t.Fatal(e)
				}
			case "public-directory":
				if e := os.Chmod(dir, 0755); e != nil {
					t.Fatal(e)
				}
			}
			before, _ := os.Lstat(path)
			if c, e := openMailOnlyChannel(ctx, o, nil); e == nil {
				closeMailOnly(t, c)
				t.Fatal("unsafe path accepted")
			}
			after, _ := os.Lstat(path)
			if before != nil && (after == nil || !os.SameFile(before, after)) {
				t.Fatal("occupied path altered")
			}
		})
	}
}
func TestMailOnlyCloseWaitsForActualHandlerDrainAndPreservesOriginal(t *testing.T) {
	ctx, o := mailOnlyFixture(t)
	started := make(chan struct{})
	release := make(chan struct{})
	c, e := openMailOnlyChannel(ctx, o, mailTransport(func(*http.Request) (*http.Response, error) {
		close(started)
		<-release
		return mailResponse(200, `{}`), nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	b, e := c.Binding()
	if e != nil {
		t.Fatal(e)
	}
	client := mailOnlyClient(b.SocketPath)
	defer client.CloseIdleConnections()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		r, e := client.Get("http://local/v1/whoami")
		if e == nil {
			r.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("fixture request never entered relay")
	}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if e = c.Close(expired); !errors.Is(e, context.Canceled) {
		t.Fatalf("undrained work claimed closed: %v", e)
	}
	if _, e = c.Binding(); e == nil {
		t.Fatal("revoked endpoint still live")
	}
	if _, e = os.Lstat(filepath.Join(o.Root, o.Environment, "mail-only-inc.closed.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("premature terminal receipt")
	}
	close(release)
	closeMailOnly(t, c)
	select {
	case <-requestDone:
	case <-ctx.Done():
		t.Fatal("local caller not drained")
	}
}
func TestMailOnlyCloseNeverUnlinksReplacement(t *testing.T) {
	ctx, o := mailOnlyFixture(t)
	c, e := openMailOnlyChannel(ctx, o, mailTransport(func(*http.Request) (*http.Response, error) { return mailResponse(200, `{}`), nil }))
	if e != nil {
		t.Fatal(e)
	}
	b, e := c.Binding()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(b.SocketPath, b.SocketPath+"-original"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(b.SocketPath, []byte("replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Binding(); e == nil {
		t.Fatal("replacement binding accepted")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e = c.Close(closeCtx); e == nil {
		t.Fatal("replacement custody claimed clean")
	}
	raw, e := os.ReadFile(b.SocketPath)
	if e != nil || string(raw) != "replacement" {
		t.Fatal("unrelated path removed")
	}
}
func TestMailOnlyLifetimeAndInvalidInputsRefuseBeforeOpen(t *testing.T) {
	ctx, o := mailOnlyFixture(t)
	for _, change := range []string{"unbounded", "canceled", "long-deadline", "bad-seat", "bad-environment", "relative-root"} {
		t.Run(change, func(t *testing.T) {
			x := o
			cctx := ctx
			switch change {
			case "unbounded":
				cctx = context.Background()
			case "canceled":
				var cancel context.CancelFunc
				cctx, cancel = context.WithCancel(ctx)
				cancel()
			case "long-deadline":
				var cancel context.CancelFunc
				cctx, cancel = context.WithTimeout(context.Background(), time.Hour)
				defer cancel()
			case "bad-seat":
				x.Seat = "foreign/seat"
			case "bad-environment":
				x.Environment = "../other"
			case "relative-root":
				x.Root = "relative"
			}
			if c, e := openMailOnlyChannel(cctx, x, nil); e == nil {
				closeMailOnly(t, c)
				t.Fatal("invalid input accepted")
			}
		})
	}
	if _, e := os.Lstat(filepath.Join(o.Root, o.Environment, "mail.sock")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("invalid open left endpoint")
	}
	life, cancel := context.WithCancel(ctx)
	c, e := openMailOnlyChannel(life, o, nil)
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	if _, e = c.Binding(); e == nil {
		t.Fatal("canceled lifetime accepted")
	}
	closeMailOnly(t, c)
}
