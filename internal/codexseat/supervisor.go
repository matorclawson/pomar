// Package codexseat runs the pinned Codex TUI in a guest. It owns thread
// identity, never tool-effect acceptance: uncertain effects remain held.
package codexseat

import (
	"bufio"
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
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/agentenv"
)

const Version = "0.160.0"

// LinuxExecutableSHA256 is the already retained native Codex ARM64 artifact
// pin. It is not a TUI, replay, or interactive acceptance qualification.
const LinuxExecutableSHA256 = "50b06603bdcdac39b714f5c3e68583c002b8ad8779ebfdaaf4932ff016b379c0"

var threadID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var ErrHeld = errors.New("Codex thread identity held; inspect the original startup record, do not start a new conversation")

// Supervisor never inherits the caller's environment or chooses a newest
// thread. StateDir and Home must be private directories inside this guest.
type Supervisor struct {
	Launch                                  *agentenv.SeatLaunch
	Seat, Binary, Home, StateDir, Workspace string
	Env                                     []string
	In                                      io.Reader
	Out                                     io.Writer
}

type record struct {
	StartupNonce        string   `json:"startup_nonce,omitempty"`
	Seat                string   `json:"seat"`
	ConfigurationSHA256 string   `json:"configuration_sha256"`
	Schema              string   `json:"schema"`
	State               string   `json:"state"`
	Thread              string   `json:"thread,omitempty"`
	Before              []string `json:"before"`
	Workspace           string   `json:"workspace"`
	BinarySHA256        string   `json:"binary_sha256"`
	Version             string   `json:"version"`
}

func privateDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("guest state path must be absolute")
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return errors.New("guest state directory must be private and not redirected")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) {
		return errors.New("guest state directory has a different owner")
	}
	return nil
}

func (s Supervisor) configurationDigest() string {
	data, _ := json.Marshal(struct{ Args, Env []string }{s.Args(""), s.Env})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s Supervisor) write(r record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.StateDir, ".thread-pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(s.StateDir, "codex-thread.json")); err != nil {
		return err
	}
	d, err := os.Open(s.StateDir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s Supervisor) read() (record, error) { return s.readAs(uint32(os.Getuid())) }
func (s Supervisor) readAs(owner uint32) (record, error) {
	var r record
	path := filepath.Join(s.StateDir, "codex-thread.json")
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return r, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 || fi.Mode().Perm()&0077 != 0 {
		return r, ErrHeld
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != owner || st.Nlink != 1 {
		return r, ErrHeld
	}
	if json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&r) != nil {
		return r, ErrHeld
	}
	if r.Seat != s.Seat || r.ConfigurationSHA256 != s.configurationDigest() || r.Schema != "pomar.codex-seat-thread/v1" || r.Version != Version || r.BinarySHA256 != LinuxExecutableSHA256 || r.Workspace != s.Workspace || (r.State != "starting" && r.State != "bound") || (r.State == "bound" && !threadID.MatchString(r.Thread)) || (r.State == "starting" && r.Thread != "") || len(r.Before) > 4096 {
		return r, ErrHeld
	}
	return r, nil
}

func (s Supervisor) rollouts() ([]string, error) {
	root := filepath.Join(s.Home, "sessions")
	var paths []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) && path == root {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return ErrHeld
		}
		if !d.IsDir() && strings.HasSuffix(path, ".jsonl") {
			paths = append(paths, path)
			if len(paths) > 4096 {
				return ErrHeld
			}
		}
		return nil
	})
	return paths, err
}

// bind finds one new CLI-root session in this exclusively owned guest home,
// using its first metadata line only. Missing/multiple identities are held.
// It never reads auth files, prompts, later transcript lines, or subagent turns.
func (s Supervisor) bind(r record) (record, error) {
	paths, err := s.rollouts()
	if err != nil {
		return r, err
	}
	before := map[string]bool{}
	for _, p := range r.Before {
		before[p] = true
	}
	var candidates []string
	for _, path := range paths {
		if before[path] {
			continue
		}
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return r, ErrHeld
		}
		fi, e := f.Stat()
		if e != nil || !fi.Mode().IsRegular() {
			f.Close()
			return r, ErrHeld
		}
		scan := bufio.NewScanner(io.LimitReader(f, 2<<20))
		scan.Buffer(make([]byte, 4096), 2<<20)
		var meta struct {
			Type    string `json:"type"`
			Payload struct {
				ID     string          `json:"id"`
				Cwd    string          `json:"cwd"`
				Source json.RawMessage `json:"source"`
				Forked *string         `json:"forked_from_id"`
			} `json:"payload"`
		}
		valid := scan.Scan() && json.Unmarshal(scan.Bytes(), &meta) == nil
		f.Close()
		if !valid {
			return r, ErrHeld
		}
		if meta.Type == "session_meta" && string(meta.Payload.Source) == `"cli"` && meta.Payload.Cwd == s.Workspace && meta.Payload.Forked == nil && threadID.MatchString(meta.Payload.ID) {
			candidates = append(candidates, meta.Payload.ID)
		}
	}
	if len(candidates) != 1 {
		return r, ErrHeld
	}
	r.State, r.Thread = "bound", candidates[0]
	if err = s.write(r); err != nil {
		return r, err
	}
	return r, nil
}

func (s Supervisor) Args(thread string) []string {
	l := s.Launch
	if l == nil {
		return nil
	}
	effort, _ := json.Marshal(l.Effort)
	args := []string{"--ask-for-approval", l.Approvals, "--sandbox", l.Sandbox, "--model", l.Model, "-c", "model_reasoning_effort=" + string(effort), "-c", fmt.Sprintf("sandbox_workspace_write.network_access=%t", *l.NetworkAccess), "--no-alt-screen", "-c", `cli_auth_credentials_store="file"`, "-c", "analytics.enabled=false", "--cd", s.Workspace}
	if thread != "" {
		args = append([]string{"resume", thread}, args...)
	}
	return args
}

type runningActor interface{ Wait() error }

func (s Supervisor) openNative() (*os.File, error) {
	if err := immutableParents(s.Binary); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.Binary, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<30 || fi.Mode().Perm()&0022 != 0 || fi.Mode().Perm()&0111 == 0 {
		f.Close()
		return nil, errors.New("Codex executable custody refused")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		f.Close()
		return nil, errors.New("Codex executable must remain owned by the guest custodian")
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil || hex.EncodeToString(h.Sum(nil)) != LinuxExecutableSHA256 {
		f.Close()
		return nil, errors.New("Codex executable differs from the pinned Linux ARM64 artifact")
	}

	return f, nil
}

// The parent retains its scope lock while the native actor inherits it.
// A trampoline closes the executable descriptor during the first exec.
func (s Supervisor) launchNative(r record, lock, f *os.File) (runningActor, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := append([]string{"codex-seat-exec", "--", s.Binary}, s.Args(r.Thread)...)
	cmd := exec.Command(self, args...)
	cmd.Env = append([]string{}, s.Env...)
	cmd.Dir = s.Workspace
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.In, s.Out, s.Out
	cmd.ExtraFiles = []*os.File{lock, f}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func (s Supervisor) Start() error { return s.start(s.openNative, s.launchNative) }
func (s Supervisor) start(open func() (*os.File, error), launch func(record, *os.File, *os.File) (runningActor, error)) error {
	if err := s.Launch.Validate(); err != nil {
		return err
	}
	if s.Launch.CWD != s.Workspace {
		return errors.New("declared workspace differs from guest materialization")
	}
	if !filepath.IsAbs(s.Binary) || !filepath.IsAbs(s.Workspace) {
		return errors.New("Codex binary and workspace must be absolute")
	}
	if err := privateDir(s.Home); err != nil {
		return err
	}
	if err := os.MkdirAll(s.StateDir, 0700); err != nil {
		return err
	}
	if err := privateDir(s.StateDir); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(s.StateDir, "actor.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return ErrActorRunning
	}
	r, err := s.read()
	fresh := false
	if errors.Is(err, os.ErrNotExist) {
		before, e := s.rollouts()
		if e != nil {
			return e
		}
		if len(before) != 0 {
			return ErrHeld
		}
		fresh = true
		nonce := make([]byte, 32)
		if _, err = rand.Read(nonce); err != nil {
			return err
		}
		r = record{StartupNonce: hex.EncodeToString(nonce), Seat: s.Seat, ConfigurationSHA256: s.configurationDigest(), Schema: "pomar.codex-seat-thread/v1", State: "starting", Before: before, Workspace: s.Workspace, BinarySHA256: LinuxExecutableSHA256, Version: Version}
	} else if err != nil {
		return err
	} else if r.State == "starting" {
		return ErrHeld
	}
	f, err := open()
	if err != nil {
		return err
	}
	defer f.Close()
	if fresh {
		if err = s.write(r); err != nil {
			return err
		}
	}
	process, err := launch(r, lock, f)
	if err != nil {
		return err
	}
	return s.waitBinding(r, process)
}

func (s Supervisor) waitBinding(r record, process runningActor) error {
	if r.State == "bound" {
		return process.Wait()
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case exit := <-done:
			if _, err := s.bind(r); err != nil {
				return ErrHeld
			}
			return exit
		case <-tick.C:
			if _, err := s.bind(r); err == nil {
				return <-done
			}
		}
	}
}

var ErrActorRunning = errors.New("Codex actor still owns this execution scope; another start is refused")

func immutableParents(binary string) error {
	for p := filepath.Dir(binary); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() || fi.Mode().Perm()&0022 != 0 {
			return errors.New("Codex helper directory custody refused")
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return errors.New("Codex helper directory must be custodian-owned")
		}
		if p == "/" {
			return nil
		}
	}
}

// ExecPinned is the guest trampoline only. Descriptor 4 is closed by the
// native ELF exec; descriptor 3 intentionally fences the whole tool scope.
func ExecPinned(argv []string) error {
	if len(argv) < 1 || !filepath.IsAbs(argv[0]) {
		return errors.New("missing pinned native argv")
	}
	if err := syscall.SetNonblock(4, false); err != nil {
		return err
	}
	syscall.CloseOnExec(4)
	return syscall.Exec("/proc/self/fd/4", argv, os.Environ())
}

func (s Supervisor) Run() error {
	in := s.In
	for {
		fmt.Fprintf(s.Out, "\nPomar Codex seat %s is idle. Type r to start/resume its bound conversation.\n> ", s.Seat)
		line, err := readCommand(in)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) == "r" {
			if err = s.Start(); err != nil {
				fmt.Fprintln(s.Out, "Codex start/resume refused:", err)
			}
		}
	}
}

// Read only the idle command, never prefetch bytes that belong to the TUI.
func readCommand(in io.Reader) (string, error) {
	var b strings.Builder
	one := make([]byte, 1)
	for {
		n, err := in.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return b.String(), nil
			}
			if b.Len() >= 4096 {
				return "", errors.New("idle command too long")
			}
			b.WriteByte(one[0])
		}
		if err != nil {
			return "", err
		}
	}
}
