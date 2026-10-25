// Package postgres runs an explicitly pinned, same-account disposable cluster.
// It is a local gate helper, not a managed service or a privileged executor.
package postgres

// sow: pomar-SOW-87 rev27 (seven-path grant in revisions22/23).
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type FilePin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
	Mode   uint32 `json:"mode"`
	Link   string `json:"link,omitempty"`
	Links  uint64 `json:"links,omitempty"` // Default1; all aliases must be inventoried inside Prefix.
}

// Tools is independently selected by the caller, then pinned by the separate
// manifest digest. It inventories the complete prefix, not just three binaries.
// OSIdentitySHA256 pins the platform's public version file; it is not a complete
// operating-system attestation or a claim that a user-owned prefix is immutable.
type Tools struct {
	Schema           string            `json:"schema"`
	Version          string            `json:"version"`
	Platform         string            `json:"platform"`
	OSIdentitySHA256 string            `json:"os_identity_sha256"`
	SourceSHA256     string            `json:"source_sha256"`
	Prefix           string            `json:"prefix"`
	Owner            uint32            `json:"owner"`
	BootstrapRole    string            `json:"bootstrap_role"`
	Files            []FilePin         `json:"files"`
	RoleProfiles     map[string]string `json:"role_profiles,omitempty"`
}

type Config struct {
	WorkRoot, Manifest, ManifestSHA256 string
	GateDir                            string
	Gate                               []string
	Env                                []string // Explicit allowlisted values only; never os.Environ().
	Extensions                         map[string]string
	RoleProfile                        string
	Whole, Startup, Stop               time.Duration
	LogBytes                           int64 // Aggregate budget across server, gate stdout and gate stderr.
}

type Result struct {
	Schema           string    `json:"schema"`
	Root             string    `json:"root"`
	ManifestSHA256   string    `json:"manifest_sha256"`
	Version          string    `json:"version"`
	Started          time.Time `json:"started"`
	Finished         time.Time `json:"finished"`
	GateExit         *int      `json:"gate_exit,omitempty"`
	GateError        string    `json:"gate_error,omitempty"`
	CleanupError     string    `json:"cleanup_error,omitempty"`
	Error            string    `json:"error,omitempty"`
	LogsComplete     bool      `json:"logs_complete"`
	CleanupConfirmed bool      `json:"cleanup_confirmed"`
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func digestOK(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}
func identifier(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func relative(s string) bool {
	return s != "" && s != "." && !filepath.IsAbs(s) && filepath.Clean(s) == s && s != ".." && !strings.HasPrefix(s, ".."+string(filepath.Separator))
}

// Reject duplicate keys as well as unknown fields and trailing documents.
func decode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func() error
	value = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		if x, ok := t.(json.Delim); ok {
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return errors.New("duplicate JSON key")
					}
					seen[s] = true
					if e = value(); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e = value(); e != nil {
						return e
					}
				}
			default:
				return errors.New("unexpected JSON delimiter")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := value(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(target)
}

func ownedDir(path string, private bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("canonical absolute directory required")
	}
	for p := path; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		m, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || m.Uid != 0 && m.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 {
			return errors.New("directory custody refused")
		}
		if p == path && (m.Uid != uint32(os.Geteuid()) || private && st.Mode().Perm() != 0700) {
			return errors.New("owned directory required")
		}
		if p == "/" {
			break
		}
	}
	return nil
}

func boundDirectory(root *os.Root, path string) error {
	if e := ownedDir(path, true); e != nil {
		return e
	}
	opened, e := root.Stat(".")
	current, ce := os.Lstat(path)
	if e != nil || ce != nil || !os.SameFile(opened, current) {
		return errors.New("invocation directory path changed; retain custody uncertainty")
	}
	return nil
}
func pinned(path string, maximum int64, owner uint32) ([]byte, error) {
	return pinnedLinks(path, maximum, owner, 1)
}
func pinnedLinks(path string, maximum int64, owner uint32, links uint64) ([]byte, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	m, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || uint64(m.Nlink) != links || m.Uid != owner || st.Mode().Perm()&0022 != 0 || st.Size() < 1 || st.Size() > maximum {
		return nil, errors.New("file custody/size refused")
	}
	b, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	now, ne := os.Lstat(path)
	if e != nil || ne != nil || !os.SameFile(st, now) || st.Size() != int64(len(b)) || after.Size() != st.Size() || !st.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("file changed while reading")
	}
	return b, nil
}
func OSIdentityPath() string {
	if runtime.GOOS == "darwin" {
		return "/System/Library/CoreServices/SystemVersion.plist"
	}
	if runtime.GOOS == "linux" {
		return "/etc/os-release"
	}
	return ""
}

// VerifyTools has no cluster/process effects. Missing pins or extra files refuse.
func VerifyTools(ctx context.Context, path, expected string) (*Tools, error) {
	if ctx == nil || !digestOK(expected) || os.Geteuid() == 0 {
		return nil, errors.New("non-root caller and explicit manifest digest required")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("absolute manifest path required")
	}
	raw, e := pinned(path, 4<<20, uint32(os.Geteuid()))
	if e != nil {
		return nil, e
	}
	if hash(raw) != expected {
		return nil, errors.New("manifest digest differs")
	}
	var t Tools
	if e = decode(raw, &t); e != nil {
		return nil, e
	}
	if t.Schema != "pomar.postgres-tools/v1" || !strings.HasPrefix(t.Version, "17.") || t.Platform != runtime.GOOS+"/"+runtime.GOARCH || !digestOK(t.SourceSHA256) || !digestOK(t.OSIdentitySHA256) || t.Owner != uint32(os.Geteuid()) || !identifier(t.BootstrapRole) || len(t.Files) == 0 || len(t.Files) > 20000 {
		return nil, errors.New("unsupported tool/platform/owner binding")
	}
	if e = ownedDir(t.Prefix, false); e != nil {
		return nil, e
	}
	osRaw, e := os.ReadFile(OSIdentityPath())
	if e != nil || hash(osRaw) != t.OSIdentitySHA256 {
		return nil, errors.New("host version identity differs")
	}
	pins := map[string]FilePin{}
	for _, p := range t.Files {
		if p.Links == 0 {
			p.Links = 1
		}
		if !relative(p.Path) || pins[p.Path].Path != "" || p.Mode&^0777 != 0 || p.Link == "" && p.Mode&0022 != 0 {
			return nil, errors.New("invalid/duplicate tool path")
		}
		if p.Link != "" {
			if p.SHA256 != "" || p.Bytes != 0 || filepath.IsAbs(p.Link) || !relative(filepath.Clean(filepath.Join(filepath.Dir(p.Path), p.Link))) {
				return nil, errors.New("escaping tool link")
			}
		} else if !digestOK(p.SHA256) || p.Bytes < 1 || p.Bytes > 128<<20 || p.Links > 20000 {
			return nil, errors.New("invalid file pin")
		}
		pins[p.Path] = p
	}
	for _, n := range []string{"bin/initdb", "bin/postgres", "bin/psql"} {
		p, ok := pins[n]
		if !ok || p.Link != "" || p.Mode&0111 == 0 {
			return nil, errors.New("required executable pin missing")
		}
	}
	for name, p := range t.RoleProfiles {
		if !identifier(name) || pins[p].Path == "" || pins[p].Link != "" {
			return nil, errors.New("reviewed role profile pin missing")
		}
	}
	seen := map[string]bool{}
	type inode struct{ device, number uint64 }
	counts := map[inode]uint64{}
	linkCounts := map[inode]uint64{}
	e = filepath.WalkDir(t.Prefix, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		st, e := os.Lstat(path)
		if e != nil {
			return e
		}
		m, ok := st.Sys().(*syscall.Stat_t)
		if !ok || m.Uid != t.Owner || st.Mode()&os.ModeSymlink == 0 && st.Mode().Perm()&0022 != 0 {
			return errors.New("tool closure custody differs")
		}
		if entry.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(t.Prefix, path)
		if e != nil {
			return e
		}
		p, ok := pins[rel]
		if !ok {
			return errors.New("unlisted tool file")
		}
		seen[rel] = true
		if st.Mode()&os.ModeSymlink != 0 {
			link, e := os.Readlink(path)
			if e != nil || p.Link == "" || link != p.Link {
				return errors.New("tool symlink differs")
			}
			resolved, e := filepath.EvalSymlinks(path)
			if e != nil {
				return e
			}
			r, e := filepath.Rel(t.Prefix, resolved)
			if e != nil || !relative(r) {
				return errors.New("tool link escapes prefix")
			}
			return nil
		}
		if p.Link != "" || uint32(st.Mode().Perm()) != p.Mode {
			return errors.New("tool mode differs")
		}
		id := inode{uint64(m.Dev), uint64(m.Ino)}
		counts[id]++
		linkCounts[id] = uint64(m.Nlink)
		b, e := pinnedLinks(path, p.Bytes, t.Owner, p.Links)
		if e != nil {
			return e
		}
		if int64(len(b)) != p.Bytes || hash(b) != p.SHA256 {
			return errors.New("tool bytes differ")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if len(seen) != len(pins) {
		return nil, errors.New("incomplete tool closure")
	}
	for id, count := range counts {
		if count != linkCounts[id] {
			return nil, errors.New("tool hardlink has an alias outside the inventoried prefix")
		}
	}
	return &t, ctx.Err()
}

func validate(c Config) error {
	if os.Geteuid() == 0 {
		return errors.New("root execution refused")
	}
	if c.Whole < time.Second || c.Whole > time.Hour || c.Startup <= 0 || c.Stop < time.Second || c.Startup+c.Stop >= c.Whole || c.LogBytes < 4096 || c.LogBytes > 64<<20 {
		return errors.New("finite whole/start/stop/log budgets required")
	}
	if len(c.Gate) == 0 || !filepath.IsAbs(c.Gate[0]) || len(c.Gate) > 256 {
		return errors.New("absolute gate executable required")
	}
	for _, a := range c.Gate {
		if strings.ContainsRune(a, 0) || len(a) > 16384 {
			return errors.New("invalid gate argv")
		}
	}
	if e := ownedDir(c.WorkRoot, true); e != nil {
		return e
	}
	if e := ownedDir(c.GateDir, false); e != nil {
		return e
	}
	// libpq and postgres interpret socket-directory lists. Refuse ambiguous roots.
	if strings.ContainsAny(c.WorkRoot, " ,\"\\\n\r\t") {
		return errors.New("socket work root contains unsupported separators")
	}
	for n, v := range c.Extensions {
		if n == "" || len(n) > 63 || len(v) == 0 || len(v) > 32 {
			return errors.New("explicit extension name/version required")
		}
		for _, r := range n {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				return errors.New("invalid extension name")
			}
		}
		for _, r := range v {
			if !(r >= '0' && r <= '9' || r == '.') {
				return errors.New("invalid extension version")
			}
		}
	}
	_, e := environment(c, "/unused", "/unused", "")
	return e
}
func environment(c Config, home, socket, role string) ([]string, error) {
	env := []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
	seen := map[string]bool{}
	for _, s := range c.Env {
		n, _, ok := strings.Cut(s, "=")
		if !ok || seen[n] || strings.ContainsRune(s, 0) || len(s) > 16384 {
			return nil, errors.New("invalid explicit environment")
		}
		switch n {
		case "PATH", "LANG", "LC_ALL", "TZ", "CI":
		default:
			return nil, errors.New("environment key not allowlisted")
		}
		seen[n] = true
		for i, v := range env {
			if strings.HasPrefix(v, n+"=") {
				env[i] = s
				ok = false
				break
			}
		}
		if ok {
			env = append(env, s)
		}
	}
	return append(env, "HOME="+home, "TMPDIR="+filepath.Join(home, "tmp"), "PGHOST="+socket, "PGPORT=5432", "PGDATABASE=postgres", "PGUSER="+role, "PGCONNECT_TIMEOUT=1", "PGPASSFILE=/dev/null", "PGSERVICEFILE=/dev/null", "PGSYSCONFDIR="+home), nil
}

type boundedLog struct {
	mu       sync.Mutex
	f        *os.File
	n, limit int64
	overflow bool
	cancel   context.CancelFunc
}

func (l *boundedLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(b)
	left := l.limit - l.n
	if int64(len(b)) > left {
		b = b[:left]
		l.overflow = true
		l.cancel()
	}
	if len(b) > 0 {
		k, e := l.f.Write(b)
		l.n += int64(k)
		if e == nil && k != len(b) {
			e = io.ErrShortWrite
		}
		if e != nil {
			l.overflow = true
			l.cancel()
			return k, e
		}
	}
	return n, nil
}
func (l *boundedLog) complete() bool { l.mu.Lock(); defer l.mu.Unlock(); return !l.overflow }
func command(ctx context.Context, path string, args, env []string, dir string, out, errout io.Writer, delay time.Duration) error {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = nil
	cmd.Stdout = out
	cmd.Stderr = errout
	cmd.WaitDelay = delay
	return cmd.Run()
}
func persist(root *os.Root, name string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	b = append(b, '\n')
	if len(b) > 128<<10 {
		return errors.New("metadata bound exceeded")
	}
	return persistBytes(root, name, b)
}

func persistBytes(root *os.Root, name string, b []byte) error {
	if len(b) > 4<<20 {
		return errors.New("policy copy bound exceeded")
	}
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	n, e := f.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	d, e := root.Open(".")
	if e != nil {
		return e
	}
	return errors.Join(d.Sync(), d.Close())
}

// Run never reuses or removes an invocation root. An interrupted/incomplete root
// remains evidence, not authority to signal a process from a saved PID.
func Run(ctx context.Context, c Config) (r Result, err error) {
	r = Result{Schema: "pomar.postgres-run/v1", Started: time.Now().UTC(), ManifestSHA256: c.ManifestSHA256}
	if ctx == nil {
		return r, errors.New("context required")
	}
	if e := validate(c); e != nil {
		return r, e
	}
	whole, cancel := context.WithDeadline(ctx, r.Started.Add(c.Whole))
	defer cancel()
	tools, e := VerifyTools(whole, c.Manifest, c.ManifestSHA256)
	if e != nil {
		return r, e
	}
	r.Version = tools.Version
	if c.RoleProfile != "" && tools.RoleProfiles[c.RoleProfile] == "" {
		return r, errors.New("unadopted role profile")
	}
	files := map[string]bool{}
	for _, p := range tools.Files {
		files[p.Path] = p.Link == ""
	}
	for name, version := range c.Extensions {
		if !files["share/extension/"+name+".control"] || !files["share/extension/"+name+"--"+version+".sql"] {
			return r, fmt.Errorf("required extension not in pinned closure: %s@%s", name, version)
		}
	}
	work, e := os.OpenRoot(c.WorkRoot)
	if e != nil {
		return r, e
	}
	defer work.Close()
	opened, e := work.Stat(".")
	current, ce := os.Lstat(c.WorkRoot)
	if e != nil || ce != nil || !os.SameFile(opened, current) {
		return r, errors.New("work root changed before creation")
	}
	name := "pg-" + rand.Text()[:10]
	if e := work.Mkdir(name, 0700); e != nil {
		return r, e
	}
	run := filepath.Join(c.WorkRoot, name)
	r.Root = run
	root, e := work.OpenRoot(name)
	if e != nil {
		return r, e
	}
	defer root.Close()
	finish := func() {
		r.Finished = time.Now().UTC()
		if err != nil {
			r.Error = err.Error()
		}
		if e := persist(root, "result.json", r); e != nil {
			err = errors.Join(err, fmt.Errorf("result persistence uncertain: %w", e))
		}
	}
	defer finish()
	socket := filepath.Join(run, "s")
	if len(filepath.Join(socket, ".s.PGSQL.5432")) >= 104 {
		return r, errors.New("owned socket path too long")
	}
	home := filepath.Join(run, "home")
	for _, n := range []string{"s", "home", "home/tmp"} {
		if e := root.Mkdir(n, 0700); e != nil {
			return r, e
		}
	}
	env, e := environment(c, home, socket, tools.BootstrapRole)
	if e != nil {
		return r, e
	}
	manifest, e := pinned(c.Manifest, 4<<20, uint32(os.Geteuid()))
	if e != nil || hash(manifest) != c.ManifestSHA256 {
		return r, errors.New("manifest changed before durable policy copy")
	}
	if e := persistBytes(root, "tools.json", manifest); e != nil {
		return r, e
	}
	if e := persist(root, "intent.json", struct {
		Config  Config    `json:"config"`
		Tools   string    `json:"tools_sha256"`
		Started time.Time `json:"started"`
	}{c, c.ManifestSHA256, r.Started}); e != nil {
		return r, e
	}
	parent, e := work.Open(".")
	if e != nil {
		return r, e
	}
	if e := errors.Join(parent.Sync(), parent.Close()); e != nil {
		return r, fmt.Errorf("invocation directory persistence uncertain: %w", e)
	}
	if e := boundDirectory(root, run); e != nil {
		return r, e
	}
	logs := make([]*boundedLog, 3)
	for i, n := range []string{"server.log", "gate.stdout", "gate.stderr"} {
		f, e := root.OpenFile(n, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return r, e
		}
		defer f.Close()
		logs[i] = &boundedLog{f: f, limit: c.LogBytes / 3, cancel: cancel}
	}
	defer func() {
		r.LogsComplete = true
		for _, l := range logs {
			if !l.complete() {
				r.LogsComplete = false
				err = errors.Join(err, errors.New("complete log budget exceeded"))
			}
			if e := l.f.Sync(); e != nil {
				r.LogsComplete = false
				err = errors.Join(err, e)
			}
		}
	}()
	activeDeadline := r.Started.Add(c.Whole - c.Stop)
	active, stopActive := context.WithDeadline(whole, activeDeadline)
	defer stopActive()
	initCtx, stopInit := context.WithTimeout(active, c.Startup)
	e = command(initCtx, filepath.Join(tools.Prefix, "bin/initdb"), []string{"-D", filepath.Join(run, "data"), "--username=" + tools.BootstrapRole, "--auth-local=trust", "--auth-host=reject", "--encoding=UTF8", "--no-locale", "--no-instructions"}, env, run, logs[0], logs[0], time.Second)
	stopInit()
	if e != nil {
		r.CleanupError = "initialization failed; retain incomplete custody"
		return r, fmt.Errorf("initdb failed: %w", e)
	}
	if e := persist(root, "start-intent.json", struct {
		Started time.Time `json:"started"`
	}{time.Now().UTC()}); e != nil {
		return r, e
	}
	if _, e := VerifyTools(active, c.Manifest, c.ManifestSHA256); e != nil {
		return r, e
	}
	if e := boundDirectory(root, run); e != nil {
		return r, e
	}
	server := exec.Command(filepath.Join(tools.Prefix, "bin/postgres"), "-D", filepath.Join(run, "data"), "-k", socket, "-h", "", "-p", "5432", "-c", "unix_socket_permissions=0700", "-c", "logging_collector=off")
	server.Env = env
	server.Dir = run
	server.Stdout = logs[0]
	server.Stderr = logs[0]
	server.WaitDelay = time.Second
	if e := active.Err(); e != nil {
		return r, e
	}
	if e := server.Start(); e != nil {
		return r, e
	}
	// Process is the exact child returned by Start, never reconstructed from PID.
	done := make(chan struct{})
	var serverErr error
	go func() { serverErr = server.Wait(); close(done) }()
	go func() {
		select {
		case <-done:
			stopActive()
		case <-active.Done():
		}
	}()
	defer func() {
		cleanupStart := time.Now()
		select {
		case <-done:
			err = errors.Join(err, errors.New("postmaster exited before requested shutdown"))
		default:
		}
		signalErr := server.Process.Signal(syscall.SIGINT)
		if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
			r.CleanupError = "owned postmaster shutdown signal failed"
			err = errors.Join(err, signalErr)
		}
		left := time.Until(r.Started.Add(c.Whole))
		if left > c.Stop {
			left = c.Stop
		}
		if left < 0 {
			left = 0
		}
		timer := time.NewTimer(left)
		defer timer.Stop()
		select {
		case <-done:
			if serverErr == nil && r.CleanupError == "" {
				r.CleanupConfirmed = true
			} else {
				r.CleanupError = "postmaster exit/stream cleanup unconfirmed"
				err = errors.Join(err, serverErr, errors.New(r.CleanupError))
			}
		case <-timer.C:
			// Kill only this still-owned child; a kill is NOT positive cluster cleanup.
			_ = server.Process.Kill()
			r.CleanupError = "shutdown deadline exceeded; retain cluster and uncertain descendants"
			err = errors.Join(err, errors.New(r.CleanupError))
			select {
			case <-done:
			case <-time.After(time.Second):
			}
		}
		for _, name := range []string{"s/.s.PGSQL.5432", "s/.s.PGSQL.5432.lock", "data/postmaster.pid"} {
			if _, e := root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
				r.CleanupConfirmed = false
				r.CleanupError = "postmaster custody markers remain or cannot be inspected"
				err = errors.Join(err, errors.New(r.CleanupError))
			}
		}
		if e := boundDirectory(root, run); e != nil {
			r.CleanupConfirmed = false
			r.CleanupError = e.Error()
			err = errors.Join(err, e)
		}
		if e := persist(root, "cleanup.json", struct {
			Started   time.Time `json:"started"`
			Confirmed bool      `json:"confirmed"`
			Error     string    `json:"error,omitempty"`
		}{cleanupStart.UTC(), r.CleanupConfirmed, r.CleanupError}); e != nil {
			r.CleanupConfirmed = false
			err = errors.Join(err, e)
		}
	}()
	if e := persist(root, "started.json", struct {
		PID int       `json:"pid_for_diagnostics_only"`
		At  time.Time `json:"at"`
	}{server.Process.Pid, time.Now().UTC()}); e != nil {
		return r, e
	}
	readyCtx, stopReady := context.WithTimeout(active, c.Startup)
	defer stopReady()
	psql := func(ctx context.Context, args []string, out io.Writer) error {
		return command(ctx, filepath.Join(tools.Prefix, "bin/psql"), append([]string{"-X", "-v", "ON_ERROR_STOP=1", "-h", socket, "-p", "5432", "-U", tools.BootstrapRole, "-d", "postgres"}, args...), env, run, out, logs[0], time.Second)
	}
	for {
		if e := readyCtx.Err(); e != nil {
			return r, fmt.Errorf("readiness deadline: %w", e)
		}
		probeCtx, endProbe := context.WithTimeout(readyCtx, time.Second)
		var out tinyBuffer
		e := psql(probeCtx, []string{"-Atc", "SELECT current_setting('listen_addresses') = '' AND inet_server_addr() IS NULL"}, &out)
		endProbe()
		if e == nil && string(out.b) == "t\n" {
			break
		}
		select {
		case <-readyCtx.Done():
			return r, readyCtx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	names := make([]string, 0, len(c.Extensions))
	for n := range c.Extensions {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sql := "CREATE EXTENSION \"" + n + "\" VERSION '" + c.Extensions[n] + "';"
		if e := psql(active, []string{"-c", sql}, logs[0]); e != nil {
			return r, fmt.Errorf("required extension unavailable: %s: %w", n, e)
		}
	}
	if c.RoleProfile != "" {
		if _, e := VerifyTools(active, c.Manifest, c.ManifestSHA256); e != nil {
			return r, e
		}
		if e := psql(active, []string{"-f", filepath.Join(tools.Prefix, tools.RoleProfiles[c.RoleProfile])}, logs[0]); e != nil {
			return r, fmt.Errorf("reviewed roles failed: %w", e)
		}
	}
	if e := active.Err(); e != nil {
		return r, e
	}
	if e := boundDirectory(root, run); e != nil {
		return r, e
	}
	if e := persist(root, "gate-intent.json", struct {
		At   time.Time `json:"at"`
		Argv []string  `json:"argv"`
	}{time.Now().UTC(), c.Gate}); e != nil {
		return r, e
	}
	gateErr := command(active, c.Gate[0], c.Gate[1:], env, c.GateDir, logs[1], logs[2], time.Second)
	code := 0
	if gateErr != nil {
		code = -1
		var exit *exec.ExitError
		if errors.As(gateErr, &exit) {
			code = exit.ExitCode()
		}
		r.GateError = gateErr.Error()
	}
	r.GateExit = &code
	if _, e := VerifyTools(active, c.Manifest, c.ManifestSHA256); e != nil {
		return r, errors.Join(gateErr, e)
	}
	return r, gateErr
}

type tinyBuffer struct{ b []byte }

func (b *tinyBuffer) Write(p []byte) (int, error) {
	if len(b.b)+len(p) > 1024 {
		return 0, errors.New("probe output exceeded bound")
	}
	b.b = append(b.b, p...)
	return len(p), nil
}
