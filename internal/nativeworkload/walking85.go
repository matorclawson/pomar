// Package nativeworkload prepares fixed workload invocations for an owner
// launcher. It does not authenticate a caller, admit or launch a process.
// sow: dt-animated-comics-SOW-01
package nativeworkload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Walking85Profile is owner-selected configuration, never caller authority.
// The receiving launcher must authenticate and freeze it, verify filesystem
// custody and the whole tool closure, and admit the complete lifetime first.
type Walking85Profile struct {
	SourceRoot, InputRoot, ScratchRoot string
	BindingPath, BindingSHA256         string
	ClosurePath                        string
	Commit, Tree, Base                 string
	NodePath, NodeSHA256, NodeVersion  string
	GitPath, GitSHA256                 string
	Mode                               string // exactly --check or --run
}

// Walking85Invocation is DATA, deliberately not exec.Cmd or seatterm.Command.
// StableExecutablePath is a requirement: relocating Node changes process.execPath
// and invalidates the Product closure. This type cannot bypass a launcher's
// executable-pinning policy. The owner must adopt a compatible launch path.
type Walking85Invocation struct {
	Executable, ExecutableSHA256 string
	Directory                    string
	Args, Env                    []string
	OutputRoot                   string
	StableExecutablePath         bool
}

type filePin struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role"`
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var nodeVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// PrepareWalking85 checks binding consistency and forms only the fixed command
// and explicit environment. It reads no file, inherits no environment and has no
// process, lease, resource-reservation or output-creation effects. In particular,
// syntactic closure completeness is not transitive toolchain qualification.
func PrepareWalking85(p Walking85Profile, binding, closure []byte) (Walking85Invocation, error) {
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	return prepareWalking85(runtime.GOOS, arch, p, binding, closure)
}

func prepareWalking85(platform, arch string, p Walking85Profile, binding, closure []byte) (Walking85Invocation, error) {
	var zero Walking85Invocation
	fail := func(reason string) (Walking85Invocation, error) { return zero, errors.New(reason) }
	if platform != "darwin" || (arch != "arm64" && arch != "x64") {
		return fail("Walking85 requires the Darwin native route")
	}
	if p.Mode != "--check" && p.Mode != "--run" {
		return fail("Walking85 permits only --check or --run")
	}
	for _, path := range []string{p.SourceRoot, p.InputRoot, p.ScratchRoot, p.BindingPath, p.ClosurePath, p.NodePath, p.GitPath} {
		if !canonicalPath(path) {
			return fail("explicit canonical absolute paths required")
		}
	}
	if filepath.Base(p.GitPath) != "git" {
		return fail("selected Git must have the fixed driver command name git")
	}
	if overlap(p.SourceRoot, p.InputRoot) || overlap(p.SourceRoot, p.ScratchRoot) || overlap(p.InputRoot, p.ScratchRoot) {
		return fail("source, DATA and scratch roots must not overlap")
	}
	ownerPaths := map[string]bool{}
	for _, path := range []string{p.BindingPath, p.ClosurePath, p.NodePath, p.GitPath} {
		if ownerPaths[path] {
			return fail("owner artifact and executable paths must be distinct")
		}
		ownerPaths[path] = true
		if overlap(p.ScratchRoot, path) || overlap(p.InputRoot, path) || overlap(p.SourceRoot, path) {
			return fail("owner binding and executable paths must be outside workload roots")
		}
	}
	if !commitPattern.MatchString(p.Commit) || !commitPattern.MatchString(p.Tree) ||
		!commitPattern.MatchString(p.Base) || p.Commit == p.Base ||
		!digestPattern.MatchString(p.NodeSHA256) || !digestPattern.MatchString(p.GitSHA256) ||
		!nodeVersionPattern.MatchString(p.NodeVersion) {
		return fail("distinct explicit source and tool identities required")
	}
	if len(binding) == 0 || len(binding) > 1<<20 || !digestPattern.MatchString(p.BindingSHA256) || sum(binding) != p.BindingSHA256 {
		return fail("bounded owner binding bytes do not match their pin")
	}
	var b struct {
		Schema string `json:"schema"`
		Source struct {
			Commit string `json:"commit"`
			Tree   string `json:"tree"`
			Base   string `json:"base"`
		} `json:"source"`
		Toolchain struct {
			Platform    string  `json:"platform"`
			Arch        string  `json:"arch"`
			NodeVersion string  `json:"nodeVersion"`
			Closure     filePin `json:"closure"`
		} `json:"toolchain"`
	}
	if uniqueJSON(binding) != nil || json.Unmarshal(binding, &b) != nil || b.Schema != "walking85-fixed-harness-v1" ||
		b.Source.Commit != p.Commit || b.Source.Tree != p.Tree || b.Source.Base != p.Base ||
		b.Toolchain.Platform != platform || b.Toolchain.Arch != arch || b.Toolchain.NodeVersion != p.NodeVersion {
		return fail("binding source, schema or native tool selection differs from owner profile")
	}
	if len(closure) == 0 || len(closure) > 8<<20 || b.Toolchain.Closure.Path != p.ClosurePath ||
		b.Toolchain.Closure.Bytes != int64(len(closure)) || !digestPattern.MatchString(b.Toolchain.Closure.SHA256) ||
		sum(closure) != b.Toolchain.Closure.SHA256 {
		return fail("bounded tool closure bytes do not match their binding")
	}
	var c struct {
		Files []filePin `json:"files"`
	}
	if uniqueJSON(closure) != nil || json.Unmarshal(closure, &c) != nil || len(c.Files) == 0 || len(c.Files) > 20000 {
		return fail("explicit bounded tool closure required")
	}
	paths, roles := map[string]bool{}, map[string]filePin{}
	for _, pin := range c.Files {
		if !canonicalPath(pin.Path) || pin.Bytes <= 0 || !digestPattern.MatchString(pin.SHA256) || paths[pin.Path] {
			return fail("invalid or duplicate closure member")
		}
		paths[pin.Path] = true
		if pin.Role != "" {
			if _, exists := roles[pin.Role]; exists {
				return fail("duplicate tool role")
			}
			roles[pin.Role] = pin
		}
	}
	for _, role := range []string{"node", "git", "npm", "npm-package", "vitest-entry", "vitest-package", "sharp-entry", "sharp-package", "sharp-native", "sharp-native-package", "sharp-libvips-package", "sharp-libvips-entry", "sharp-libvips-versions"} {
		if _, ok := roles[role]; !ok {
			return fail("missing required tool role: " + role)
		}
	}
	if roles["node"].Path != p.NodePath || roles["node"].SHA256 != p.NodeSHA256 ||
		roles["git"].Path != p.GitPath || roles["git"].SHA256 != p.GitSHA256 {
		return fail("Node or Git path/pin differs from owner selection")
	}
	output := filepath.Join(p.ScratchRoot, "output")
	return Walking85Invocation{
		Executable: p.NodePath, ExecutableSHA256: p.NodeSHA256, Directory: p.SourceRoot,
		Args:       []string{filepath.Join(p.SourceRoot, "qualification/walking85/run.mjs"), p.Mode},
		OutputRoot: output, StableExecutablePath: true,
		Env: []string{"HOME=" + filepath.Join(p.ScratchRoot, "home"), "TMPDIR=" + filepath.Join(p.ScratchRoot, "tmp"),
			"PATH=" + filepath.Dir(p.GitPath) + ":" + filepath.Dir(p.NodePath) + ":/usr/bin:/bin", "LC_ALL=C", "TZ=UTC",
			"DT_WALKING85_BINDING=" + p.BindingPath, "DT_WALKING85_INPUT_ROOT=" + p.InputRoot,
			"DT_WALKING85_OUTPUT_ROOT=" + output, "DT_NATIVE_SOURCE_ROOT=" + p.SourceRoot},
	}, nil
}

func canonicalPath(p string) bool {
	return len(p) > 1 && len(p) <= 4096 && filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n:")
}

func overlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}

func sum(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting exceeds bound")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			seen := map[string]bool{}
			for d.More() {
				if delimiter == '{' {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return errors.New("invalid or duplicate JSON field")
					}
					seen[name] = true
				}
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("one JSON value required")
	}
	return nil
}
