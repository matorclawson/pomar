// sow: zeroemployee-SOW-180
// Source preparation only. This companion neither admits nor qualifies a guest.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	schema        = "pomar.creator-verification/v1"
	sourceMode    = "disposable-copy-of-readonly-input"
	creatorHead   = "59d423e0d2f0feadd2b7f96b934ade4fc85f7a14"
	inputRoot     = "/pomar/inputs/creator-source"
	cacheRoot     = "/pomar/inputs/creator-cache"
	toolRoot      = "/pomar/tools/creator-verification/bin"
	workRoot      = "/pomar/work/creator-verification"
	reportRoot    = "/pomar/outputs/creator-verification"
	workloadName  = "creator-workload"
	manifestLimit = 1048576
)

type filePin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type limits struct {
	StdoutBytes    int64 `json:"stdout_bytes"`
	StderrBytes    int64 `json:"stderr_bytes"`
	VerifySeconds  int64 `json:"verify_seconds"`
	DoctorSeconds  int64 `json:"doctor_seconds"`
	CleanupSeconds int64 `json:"cleanup_seconds"`
	WholeSeconds   int64 `json:"whole_seconds"`
	OutputBytes    int64 `json:"output_bytes"`
	OutputFiles    int64 `json:"output_files"`
}

// All paths are relative inventories beneath compiled-in roots. There is no
// command, identity, mount, executable-path or environment selector in the input.
type manifest struct {
	Schema        string    `json:"schema"`
	SourceMode    string    `json:"source_mode"`
	SourceCommit  string    `json:"source_commit"`
	SourceTree    string    `json:"source_tree"`
	ClosureSHA256 string    `json:"closure_sha256"`
	SourceFiles   []filePin `json:"source_files"`
	CacheFiles    []filePin `json:"cache_files"`
	Tools         []filePin `json:"tools"`
	Limits        limits    `json:"limits"`
}

func keys(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, name := range names {
		m[name] = true
	}
	return m
}

var objectKeys = map[string]map[string]bool{
	"root":   keys("schema", "source_mode", "source_commit", "source_tree", "closure_sha256", "source_files", "cache_files", "tools", "limits"),
	"pin":    keys("path", "sha256", "bytes"),
	"limits": keys("stdout_bytes", "stderr_bytes", "verify_seconds", "doctor_seconds", "cleanup_seconds", "whole_seconds", "output_bytes", "output_files"),
}

// Validate exact decoded key bytes BEFORE struct decoding. encoding/json alone
// accepts duplicate keys and Unicode case-fold aliases even with unknown-field
// refusal enabled. Each object is closed and every member is required.
func exactObject(d *json.Decoder, kind string) error {
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return errors.New("object_required")
	}
	seen := make(map[string]bool)
	for d.More() {
		t, err = d.Token()
		name, ok := t.(string)
		if err != nil || !ok || !objectKeys[kind][name] || seen[name] {
			return errors.New("key_refused")
		}
		seen[name] = true
		if kind == "root" && name == "limits" {
			if err := exactObject(d, "limits"); err != nil {
				return err
			}
		} else if kind == "root" && (name == "source_files" || name == "cache_files" || name == "tools") {
			t, err = d.Token()
			if err != nil || t != json.Delim('[') {
				return errors.New("array_required")
			}
			count := 0
			for d.More() {
				count++
				if count > 16384 {
					return errors.New("inventory_limit")
				}
				if err := exactObject(d, "pin"); err != nil {
					return err
				}
			}
			t, err = d.Token()
			if err != nil || t != json.Delim(']') {
				return errors.New("array_end")
			}
		} else {
			t, err = d.Token()
			if err != nil {
				return errors.New("invalid_scalar")
			}
			switch t.(type) {
			case string, json.Number:
			default:
				return errors.New("scalar_required")
			}
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') || len(seen) != len(objectKeys[kind]) {
		return errors.New("incomplete_object")
	}
	return nil
}

func parseManifest(b []byte) (manifest, error) {
	var m manifest
	if len(b) == 0 || len(b) > manifestLimit || !utf8.Valid(b) {
		return m, errors.New("manifest_size_or_encoding")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := exactObject(d, "root"); err != nil {
		return m, err
	}
	if _, err := d.Token(); err != io.EOF {
		return m, errors.New("trailing_json")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, errors.New("manifest_types")
	}
	return m, m.validate()
}

func digest(s string, size int) bool {
	if len(s) != size || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func relative(s string) bool {
	return s != "" && len(s) <= 4096 && !strings.ContainsAny(s, "\\\x00\r\n") && !filepath.IsAbs(s) && filepath.ToSlash(filepath.Clean(s)) == s && s != "." && s != ".." && !strings.HasPrefix(s, "../") && s != ".git" && !strings.HasPrefix(s, ".git/")
}

func validatePins(pins []filePin) error {
	if len(pins) == 0 || len(pins) > 16384 {
		return errors.New("inventory_size")
	}
	seen := make(map[string]bool)
	for _, p := range pins {
		if !relative(p.Path) || seen[p.Path] || !digest(p.SHA256, 64) || p.Bytes < 0 || p.Bytes > 1<<30 {
			return errors.New("pin_refused")
		}
		seen[p.Path] = true
	}
	return nil
}

func (m manifest) validate() error {
	if m.Schema != schema || m.SourceMode != sourceMode || m.SourceCommit != creatorHead || !digest(m.SourceTree, 40) || !digest(m.ClosureSHA256, 64) {
		return errors.New("identity_refused")
	}
	for _, pins := range [][]filePin{m.SourceFiles, m.CacheFiles, m.Tools} {
		if err := validatePins(pins); err != nil {
			return err
		}
	}
	// Tool names/locations are fixed, not caller-selected executables.
	want := keys("git", "make", "uv", "node", "python", "sh")
	for _, p := range m.Tools {
		delete(want, p.Path)
	}
	if len(want) != 0 {
		return errors.New("tool_set")
	}
	if closureDigest(m) != m.ClosureSHA256 {
		return errors.New("closure_binding")
	}
	l := m.Limits
	if l.StdoutBytes < 1 || l.StdoutBytes > 8388608 || l.StderrBytes < 1 || l.StderrBytes > 8388608 || l.OutputBytes < 1 || l.OutputBytes > 1073741824 || l.OutputFiles < 1 || l.OutputFiles > 4096 || l.VerifySeconds < 1 || l.VerifySeconds > 600 || l.DoctorSeconds < 1 || l.DoctorSeconds > 60 || l.CleanupSeconds < 1 || l.CleanupSeconds > 60 || l.WholeSeconds < 1 || l.WholeSeconds > 720 || l.VerifySeconds+l.DoctorSeconds+l.CleanupSeconds > l.WholeSeconds {
		return errors.New("limits_refused")
	}
	return nil
}

// This binds the declared materialized inventories. It is not registry
// provenance, dependency resolution or an independently verified guest image.
func closureDigest(m manifest) string {
	sorted := func(p []filePin) []filePin {
		q := append([]filePin(nil), p...)
		sort.Slice(q, func(i, j int) bool { return q[i].Path < q[j].Path })
		return q
	}
	b, _ := json.Marshal(struct {
		Source []filePin `json:"source"`
		Tools  []filePin `json:"tools"`
		Cache  []filePin `json:"cache"`
	}{sorted(m.SourceFiles), sorted(m.Tools), sorted(m.CacheFiles)})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func noLinks(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute_required")
	}
	part := string(filepath.Separator)
	for _, name := range strings.Split(strings.TrimPrefix(filepath.Clean(path), part), part) {
		part = filepath.Join(part, name)
		info, err := os.Lstat(part)
		if err != nil {
			return errors.New("path_unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink_refused")
		}
	}
	return nil
}

// Inventory all regular materialized inputs, including untracked extras. Git
// administrative data is deliberately excluded and checked by fixed git reads.
func inventory(ctx context.Context, root string, maxBytes, maxFiles int64, skipGit bool) ([]filePin, error) {
	if err := noLinks(root); err != nil {
		return nil, err
	}
	var pins []filePin
	var total int64
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return errors.New("inventory_deadline")
		}
		if walkErr != nil {
			return errors.New("inventory_read")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return errors.New("inventory_path")
		}
		if rel == "." {
			return nil
		}
		if skipGit && rel == ".git" {
			if e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
				return errors.New("git_directory_required")
			}
			return filepath.SkipDir
		}
		if e.IsDir() {
			return nil
		}
		// The pinned Creator tree has precisely this Git symlink. Bind its
		// literal target bytes, never hash a dereferenced arbitrary link. This
		// exception is source-only; caches, tools and outputs still refuse links.
		if skipGit && rel == ".node-version" && e.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil || target != "packages/publication-core/.node-version" {
				return errors.New("source_link_refused")
			}
			if err := noLinks(filepath.Join(root, target)); err != nil {
				return errors.New("source_link_target")
			}
			total += int64(len(target))
			if total > maxBytes || int64(len(pins)+1) > maxFiles {
				return errors.New("inventory_limit")
			}
			h := sha256.Sum256([]byte(target))
			pins = append(pins, filePin{rel, hex.EncodeToString(h[:]), int64(len(target))})
			return nil
		}
		if !e.Type().IsRegular() {
			return errors.New("special_file_refused")
		}
		info, err := e.Info()
		if err != nil {
			return errors.New("inventory_stat")
		}
		if info.Size() < 0 || info.Size() > maxBytes-total || int64(len(pins)+1) > maxFiles {
			return errors.New("inventory_limit")
		}
		total += info.Size()
		f, err := os.Open(path)
		if err != nil {
			return errors.New("inventory_open")
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(f, info.Size()+1))
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil || n != info.Size() {
			return errors.New("inventory_changed")
		}
		pins = append(pins, filePin{filepath.ToSlash(rel), hex.EncodeToString(h.Sum(nil)), n})
		return nil
	})
	sort.Slice(pins, func(i, j int) bool { return pins[i].Path < pins[j].Path })
	return pins, err
}

func samePins(a, b []filePin) bool {
	if len(a) != len(b) {
		return false
	}
	want := make(map[string]filePin, len(a))
	for _, p := range a {
		want[p.Path] = p
	}
	for _, p := range b {
		if want[p.Path] != p {
			return false
		}
	}
	return true
}

type stepResult struct {
	Name           string `json:"name"`
	Exit           *int   `json:"exit"`
	Failure        string `json:"failure"`
	StdoutBytes    int64  `json:"stdout_bytes"`
	StderrBytes    int64  `json:"stderr_bytes"`
	StdoutSHA256   string `json:"stdout_sha256"`
	StderrSHA256   string `json:"stderr_sha256"`
	LogObservation string `json:"log_observation"`
	Quiescence     string `json:"quiescence"`
}

type report struct {
	Schema               string       `json:"schema"`
	Evidence             string       `json:"evidence_source"`
	SourceMode           string       `json:"source_mode"`
	SourceCommit         string       `json:"source_commit"`
	SourceTree           string       `json:"source_tree"`
	Outcome              string       `json:"outcome"`
	Failure              string       `json:"failure"`
	Steps                []stepResult `json:"steps"`
	OriginalBefore       []filePin    `json:"original_before"`
	OriginalAfter        []filePin    `json:"original_after"`
	WorkloadAfterTree    string       `json:"workload_after_tree"`
	Quiescence           string       `json:"quiescence"`
	Cleanup              string       `json:"cleanup"`
	CleanupBudgetSeconds int64        `json:"cleanup_budget_seconds"`
	Limitations          string       `json:"limitations"`
}

type executor interface {
	Step(context.Context, string, time.Duration, int64, int64) stepResult
}

// A completed leader never proves guest quiescence. Even two zero exits leave
// UNKNOWN until independent custody and actual guest teardown are received.
func sequence(ctx context.Context, l limits, e executor) report {
	r := report{Schema: schema, Evidence: "SELF_REPORTED", SourceMode: sourceMode, SourceCommit: creatorHead, Outcome: "UNKNOWN", Quiescence: "UNKNOWN", Cleanup: "GUEST_TEARDOWN_REQUIRED", Limitations: "Before/after snapshots do not exclude transient tampering; process groups do not cover escaped descendants; no OS-deny or signed-result claim."}
	r.CleanupBudgetSeconds = l.CleanupSeconds
	var stdout, stderr int64
	for _, step := range []struct {
		name    string
		seconds int64
	}{{"verify", l.VerifySeconds}, {"doctor", l.DoctorSeconds}} {
		if ctx.Err() != nil {
			r.Outcome, r.Failure = "FAILURE", "whole_deadline"
			break
		}
		s := e.Step(ctx, step.name, time.Duration(step.seconds)*time.Second, l.StdoutBytes-stdout, l.StderrBytes-stderr)
		stdout += s.StdoutBytes
		stderr += s.StderrBytes
		r.Steps = append(r.Steps, s)
		if s.Failure != "" || s.Exit == nil || *s.Exit != 0 || stdout > l.StdoutBytes || stderr > l.StderrBytes {
			r.Outcome, r.Failure = "FAILURE", "gate_or_limit_failure"
			break
		}
	}
	return r
}

type guestExecutor struct {
	uid, gid                 uint32
	output                   string
	work                     string
	make                     string
	env                      []string
	outputBytes, outputFiles int64
	artifacts                string
}

func outputWithin(ctx context.Context, root string, bytesLimit, fileLimit int64) error {
	if err := noLinks(root); err != nil {
		return err
	}
	var size, files int64
	return filepath.WalkDir(root, func(_ string, e fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return errors.New("output_deadline")
		}
		if err != nil {
			return errors.New("output_unknown")
		}
		if e.IsDir() {
			return nil
		}
		if !e.Type().IsRegular() {
			return errors.New("output_special")
		}
		i, err := e.Info()
		if err != nil {
			return errors.New("output_unknown")
		}
		files++
		if i.Size() < 0 || i.Size() > bytesLimit-size || files > fileLimit {
			return errors.New("output_limit")
		}
		size += i.Size()
		return nil
	})
}

func logSize(f *os.File) int64 {
	i, err := f.Stat()
	if err != nil {
		return -1
	}
	return i.Size()
}

func hashLog(ctx context.Context, path string, cap int64) (string, error) {
	if ctx.Err() != nil {
		return "", errors.New("log_deadline")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("log_read")
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || i.Size() > cap {
		return "", errors.New("log_limit")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, cap+1))
	after, afterErr := f.Stat()
	if err != nil || afterErr != nil || ctx.Err() != nil || n > cap || n != i.Size() || after.Size() != n {
		return "", errors.New("log_changed_or_unknown")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (e guestExecutor) Step(parent context.Context, name string, deadline time.Duration, outLimit, errLimit int64) (r stepResult) {
	r = stepResult{Name: name, Quiescence: "UNKNOWN"}
	if (name != "verify" && name != "doctor") || outLimit < 1 || errLimit < 1 {
		r.Failure = "step_refused"
		return r
	}
	ctx, cancel := context.WithTimeout(parent, deadline)
	defer cancel()
	out, err := os.OpenFile(filepath.Join(e.output, name+".stdout"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		r.Failure = "log_create"
		return r
	}
	defer out.Close()
	errout, err := os.OpenFile(filepath.Join(e.output, name+".stderr"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		r.Failure = "log_create"
		return r
	}
	defer errout.Close()
	defer func() {
		observation, stop := context.WithTimeout(parent, time.Second)
		defer stop()
		r.StdoutBytes, r.StderrBytes = logSize(out), logSize(errout)
		var outErr, errErr error
		r.StdoutSHA256, outErr = hashLog(observation, out.Name(), outLimit)
		r.StderrSHA256, errErr = hashLog(observation, errout.Name(), errLimit)
		r.LogObservation = "SELF_REPORTED_SNAPSHOT_NOT_QUIESCENCE"
		if outErr != nil || errErr != nil {
			r.LogObservation = "UNKNOWN"
			if r.Failure == "" {
				r.Failure = "log_hash_or_unknown"
			}
		}
	}()
	cmd := exec.Command(e.make, "SHELL="+filepath.Join(toolRoot, "sh"), name)
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = e.work, e.env, out, errout
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: e.uid, Gid: e.gid, Groups: []uint32{}}}
	// Observe Start through the same deadline. A late start is killed/reaped by
	// its owner goroutine; an unconfirmed observation still requires teardown.
	started := make(chan error, 1)
	go func() {
		err := cmd.Start()
		started <- err
	}()
	select {
	case err = <-started:
		if err != nil {
			r.Failure = "start_failure"
			return r
		}
	case <-ctx.Done():
		r.Failure = "start_deadline"
		go func() {
			if err := <-started; err == nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				_ = cmd.Wait()
			}
		}()
		return r
	}
	defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err = <-done:
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					r.Failure = "wait_failure"
				} else {
					code = exit.ExitCode()
				}
			}
			r.Exit = &code
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			r.StdoutBytes, r.StderrBytes = logSize(out), logSize(errout)
			if r.StdoutBytes < 0 || r.StderrBytes < 0 || r.StdoutBytes > outLimit || r.StderrBytes > errLimit {
				r.Failure = "log_limit_or_stat"
			}
			if err := outputWithin(ctx, e.artifacts, e.outputBytes, e.outputFiles); err != nil {
				r.Failure = "output_limit_or_snapshot"
			}
			return r
		case <-ctx.Done():
			if r.Failure == "" {
				r.Failure = "step_deadline"
			}
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			r.StdoutBytes, r.StderrBytes = logSize(out), logSize(errout)
			// Wait goroutine owns eventual reap; never block here on a child or
			// inherited descriptor. Guest owner must establish actual cleanup.
			return r
		case <-tick.C:
			if logSize(out) < 0 || logSize(errout) < 0 || logSize(out) > outLimit || logSize(errout) > errLimit {
				cancel()
				r.Failure = "log_limit"
			}
			if err := outputWithin(ctx, e.artifacts, e.outputBytes, e.outputFiles); err != nil {
				cancel()
				r.Failure = "output_limit_or_unknown"
			}
		}
	}
}

func protected(ctx context.Context, path string, uid uint32) error {
	if err := noLinks(path); err != nil {
		return err
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		if ctx.Err() != nil {
			return errors.New("protected_deadline")
		}
		i, err := os.Stat(parent)
		if err != nil || i.Mode().Perm()&0022 != 0 {
			return errors.New("protected_parent")
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid == uid || s.Uid != uint32(os.Geteuid()) {
			return errors.New("protected_parent")
		}
		if parent == string(filepath.Separator) {
			break
		}
	}
	return filepath.WalkDir(path, func(_ string, e fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return errors.New("protected_deadline")
		}
		if err != nil {
			return errors.New("protected_read")
		}
		i, err := e.Info()
		if err != nil || i.Mode()&(os.ModeSymlink|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 || i.Mode().Perm()&0022 != 0 {
			return errors.New("protected_permissions")
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid == uid || s.Uid != uint32(os.Geteuid()) {
			return errors.New("protected_owner")
		}
		return nil
	})
}

func workloadOwned(ctx context.Context, root string, uid uint32) error {
	if err := noLinks(root); err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return errors.New("workload_owner_deadline")
		}
		if err != nil {
			return errors.New("workload_owner_unknown")
		}
		i, err := e.Info()
		if err != nil {
			return errors.New("workload_owner_unknown")
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != uid || (i.Mode()&os.ModeSymlink == 0 && i.Mode().Perm()&0022 != 0) {
			return errors.New("workload_owner_refused")
		}
		if !i.IsDir() && i.Mode()&os.ModeSymlink == 0 && (!i.Mode().IsRegular() || s.Nlink != 1) {
			return errors.New("workload_link_refused")
		}
		if i.Mode()&os.ModeSymlink != 0 {
			rel, err := filepath.Rel(root, path)
			target, linkErr := os.Readlink(path)
			if err != nil || linkErr != nil || rel != ".node-version" || target != "packages/publication-core/.node-version" {
				return errors.New("workload_link_refused")
			}
		}
		return nil
	})
}

// Read-only git inspection uses pinned git, no pager, hooks, external diff,
// textconv, replace objects or ambient global/system configuration. Output is
// bounded on regular files, never captured through a workload-owned pipe.
func gitRead(ctx context.Context, root, label string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := os.OpenFile(filepath.Join(reportRoot, label+".git.stdout"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return "", errors.New("git_log_create")
	}
	defer out.Close()
	errout, err := os.OpenFile(filepath.Join(reportRoot, label+".git.stderr"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", errors.New("git_log_create")
	}
	defer errout.Close()
	argv := []string{"--no-pager", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "safe.directory=" + root, "-C", root}
	cmd := exec.CommandContext(ctx, filepath.Join(toolRoot, "git"), append(argv, args...)...)
	cmd.Env = []string{"PATH=" + toolRoot, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "HOME=" + reportRoot, "LANG=C"}
	cmd.Stdout, cmd.Stderr = out, errout
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	finished := false
	for !finished {
		select {
		case err = <-done:
			finished = true
		case <-ctx.Done():
			return "", errors.New("git_read_deadline")
		case <-tick.C:
			if logSize(out) < 0 || logSize(errout) < 0 || logSize(out) > manifestLimit || logSize(errout) > manifestLimit {
				cancel()
				return "", errors.New("git_log_limit")
			}
		}
	}
	if err != nil || logSize(out) < 0 || logSize(errout) < 0 || logSize(out) > manifestLimit || logSize(errout) > manifestLimit {
		return "", errors.New("git_read_failure")
	}
	if _, err := out.Seek(0, 0); err != nil {
		return "", errors.New("git_read_failure")
	}
	b, err := io.ReadAll(io.LimitReader(out, manifestLimit+1))
	return strings.TrimSpace(string(b)), err
}

func verifyInventory(ctx context.Context, root string, want []filePin, skipGit bool) error {
	got, err := inventory(ctx, root, 1<<30, 16384, skipGit)
	if err != nil || !samePins(want, got) {
		return errors.New("input_inventory_mismatch")
	}
	return nil
}

func run(m manifest) report {
	r := report{Schema: schema, Evidence: "SELF_REPORTED", SourceMode: sourceMode, SourceCommit: m.SourceCommit, SourceTree: m.SourceTree, Outcome: "FAILURE", Quiescence: "UNKNOWN", Cleanup: "GUEST_TEARDOWN_REQUIRED", Limitations: "No OS-deny, mount-enforcement, guest admission or signed-result claim. Before/after hashes cannot exclude transient tampering."}
	fail := func(code string) report { r.Failure = code; return r }
	if err := m.validate(); err != nil {
		return fail("manifest_refused")
	}
	r.CleanupBudgetSeconds = m.Limits.CleanupSeconds
	// The final cleanup allocation belongs to the independent guest owner,
	// not to additional workload time inside this companion.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.Limits.WholeSeconds-m.Limits.CleanupSeconds)*time.Second)
	defer cancel()
	if os.Geteuid() != 0 {
		return fail("receiver_collector_required")
	}
	u, err := user.Lookup(workloadName)
	if err != nil {
		return fail("receiver_workload_user_required")
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil || uid == 0 {
		return fail("distinct_user_required")
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil || gid == 0 {
		return fail("distinct_group_required")
	}
	for _, p := range []string{inputRoot, cacheRoot, toolRoot, reportRoot} {
		if err := protected(ctx, p, uint32(uid)); err != nil {
			return fail("protected_root_refused")
		}
	}
	entries, err := os.ReadDir(reportRoot)
	if err != nil || len(entries) != 0 {
		return fail("fresh_report_root_required")
	}
	if err := verifyInventory(ctx, toolRoot, m.Tools, false); err != nil {
		return fail("tool_inventory_mismatch")
	}
	if err := verifyInventory(ctx, cacheRoot, m.CacheFiles, false); err != nil {
		return fail("cache_inventory_mismatch")
	}
	if err := verifyInventory(ctx, inputRoot, m.SourceFiles, true); err != nil {
		return fail("source_inventory_mismatch")
	}
	r.OriginalBefore = m.SourceFiles
	copyRoot := filepath.Join(workRoot, "source")
	if err := noLinks(copyRoot); err != nil {
		return fail("workload_copy_required")
	}
	if err := workloadOwned(ctx, copyRoot, uint32(uid)); err != nil {
		return fail("workload_copy_owner_or_link")
	}
	if err := verifyInventory(ctx, copyRoot, m.SourceFiles, true); err != nil {
		return fail("workload_copy_mismatch")
	}
	for i, root := range []string{inputRoot, copyRoot} {
		head, err := gitRead(ctx, root, fmt.Sprintf("before-%d-head", i), "rev-parse", "HEAD")
		if err != nil || head != creatorHead {
			return fail("source_head_mismatch")
		}
		tree, err := gitRead(ctx, root, fmt.Sprintf("before-%d-tree", i), "rev-parse", "HEAD^{tree}")
		if err != nil || tree != m.SourceTree {
			return fail("source_tree_mismatch")
		}
		status, err := gitRead(ctx, root, fmt.Sprintf("before-%d-status", i), "status", "--porcelain", "--untracked-files=all")
		if err != nil || status != "" {
			return fail("source_dirty")
		}
	}
	// The receiver, not this program, provisions/seeds the private workload
	// directories and adopts complete offline build/runtime cache closure.
	for _, p := range []string{"home", "tmp", "cache", "artifacts", "artifacts/dist", "artifacts/site", "mypy"} {
		path := filepath.Join(workRoot, p)
		if err := noLinks(path); err != nil {
			return fail("private_scratch_required")
		}
		i, err := os.Stat(path)
		if err != nil || !i.IsDir() {
			return fail("private_scratch_required")
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != uint32(uid) || i.Mode().Perm()&0022 != 0 {
			return fail("scratch_owner_refused")
		}
	}
	if err := verifyInventory(ctx, filepath.Join(workRoot, "cache"), m.CacheFiles, false); err != nil {
		return fail("workload_cache_mismatch")
	}
	if err := workloadOwned(ctx, filepath.Join(workRoot, "cache"), uint32(uid)); err != nil {
		return fail("workload_cache_owner_or_link")
	}
	env := []string{"PATH=" + toolRoot, "HOME=" + filepath.Join(workRoot, "home"), "TMPDIR=" + filepath.Join(workRoot, "tmp"), "XDG_CONFIG_HOME=" + filepath.Join(workRoot, "home"), "XDG_CACHE_HOME=" + filepath.Join(workRoot, "cache"), "UV_CACHE_DIR=" + filepath.Join(workRoot, "cache"), "UV_OFFLINE=1", "UV_FROZEN=1", "UV_PYTHON_DOWNLOADS=never", "PYTHONDONTWRITEBYTECODE=1", "PYTEST_ADDOPTS=-p no:cacheprovider", "MYPY_CACHE_DIR=" + filepath.Join(workRoot, "mypy"), "DIST_DIR=" + filepath.Join(workRoot, "artifacts/dist"), "SITE_DIR=" + filepath.Join(workRoot, "artifacts/site"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "LANG=C.UTF-8"}
	e := guestExecutor{uint32(uid), uint32(gid), reportRoot, copyRoot, filepath.Join(toolRoot, "make"), env, m.Limits.OutputBytes, m.Limits.OutputFiles, filepath.Join(workRoot, "artifacts")}
	s := sequence(ctx, m.Limits, e)
	r.Outcome, r.Failure, r.Steps = s.Outcome, s.Failure, s.Steps
	after, err := inventory(ctx, inputRoot, 1<<30, 16384, true)
	r.OriginalAfter = after
	if err != nil || !samePins(m.SourceFiles, after) {
		return fail("original_changed_or_unknown")
	}
	for _, root := range []string{inputRoot, copyRoot} {
		label := "after-original"
		if root == copyRoot {
			label = "after-copy"
		}
		head, err := gitRead(ctx, root, label+"-head", "rev-parse", "HEAD")
		if err != nil || head != creatorHead {
			return fail("after_head_changed_or_unknown")
		}
		if _, err := gitRead(ctx, root, label+"-diff", "diff", "--no-ext-diff", "--no-textconv", "--exit-code", "HEAD", "--"); err != nil {
			return fail("after_diff_or_unknown")
		}
		status, err := gitRead(ctx, root, label+"-status", "status", "--porcelain", "--untracked-files=all")
		if err != nil || status != "" {
			return fail("after_dirty_or_unknown")
		}
		tree, err := gitRead(ctx, root, label+"-tree", "rev-parse", "HEAD^{tree}")
		if root == copyRoot {
			r.WorkloadAfterTree = tree
		}
		if err != nil || tree != m.SourceTree {
			return fail("after_tree_or_unknown")
		}
	}
	return r
}

func main() {
	// A fixed guest entrypoint, never an admission client. Its invocation itself
	// requires independently adopted source/tools/cache/users/guest and a window.
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: creator-verification MANIFEST")
		os.Exit(2)
	}
	if err := noLinks(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "manifest_path_refused")
		os.Exit(2)
	}
	i, err := os.Stat(os.Args[1])
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0022 != 0 {
		fmt.Fprintln(os.Stderr, "manifest_owner_refused")
		os.Exit(2)
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) {
		fmt.Fprintln(os.Stderr, "manifest_owner_refused")
		os.Exit(2)
	}
	executable, err := os.Executable()
	check, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err != nil || protected(check, executable, ^uint32(0)) != nil {
		fmt.Fprintln(os.Stderr, "collector_path_refused")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest_unavailable")
		os.Exit(2)
	}
	b, err := io.ReadAll(io.LimitReader(f, manifestLimit+1))
	_ = f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest_unreadable")
		os.Exit(2)
	}
	m, err := parseManifest(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest_refused")
		os.Exit(2)
	}
	r := run(m)
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		os.Exit(125)
	}
	// Independently observed guest teardown/result receiving is deliberately not
	// supplied by this companion. UNKNOWN is never returned as a clean success.
	os.Exit(125)
}
