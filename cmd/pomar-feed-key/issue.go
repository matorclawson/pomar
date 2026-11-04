package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedinput"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedissuer"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

type issuanceInput struct {
	Policy          releasefeedissuer.Policy `json:"policy"`
	InputsDirectory string                   `json:"inputs_directory"`
}

func protectedPolicy(path string) ([]byte, error) {
	parent := filepath.Dir(path)
	info, e := os.Lstat(parent)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0755 {
		return nil, fmt.Errorf("root policy parent must be real0755")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return nil, fmt.Errorf("root policy parent owner")
	}
	if e := noACL(parent); e != nil {
		return nil, e
	}
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0644 || before.Size() > 65536 {
		return nil, fmt.Errorf("root policy leaf metadata")
	}
	st, ok = before.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Nlink != 1 {
		return nil, fmt.Errorf("root policy leaf owner")
	}
	if e := noACL(path); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(before, actual) {
		return nil, fmt.Errorf("root policy changed")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(raw) > 65536 {
		return nil, fmt.Errorf("root policy read incomplete")
	}
	return raw, nil
}

type artifactRoot interface {
	releasefeedinput.Root
	Close() error
}

func readIssueInputs(in issuanceInput) (map[string][]byte, []byte, error) {
	return readIssueInputsUsingRoot(in, func(path string) (artifactRoot, error) { return os.OpenRoot(path) })
}

// The factory is internal dependency injection for descriptor-boundary tests,
// never a command argument or a configurable privileged operation.
func readIssueInputsUsingRoot(in issuanceInput, openRoot func(string) (artifactRoot, error)) (map[string][]byte, []byte, error) {
	if !filepath.IsAbs(in.InputsDirectory) || len(in.Policy.Files) > 18 {
		return nil, nil, fmt.Errorf("input inventory invalid")
	}
	root, e := openRoot(in.InputsDirectory)
	if e != nil {
		return nil, nil, e
	}
	defer root.Close()
	files := map[string][]byte{}
	var receipt []byte
	names := []string{"receipt.json"}
	for n := range in.Policy.Files {
		names = append(names, n)
	}
	for _, n := range names {
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,199}$`).MatchString(n) {
			return nil, nil, fmt.Errorf("input filename invalid")
		}
		limit := releasefeedinput.MaxBytes
		switch n {
		case "release.json":
			limit = 131072
		case "receipt.json":
			limit = 1048576
		case "SHA256SUMS":
			limit = 16384
		}
		raw, e := releasefeedinput.ReadRegular(root, n, limit)
		if e != nil {
			return nil, nil, e
		}
		if n == "receipt.json" {
			receipt = raw
		} else {
			files[n] = raw
		}
	}
	return files, receipt, nil
}

func issue(c config, root *os.Root, policyPath, publicBase string, out io.Writer) error {
	raw, e := protectedPolicy(policyPath)
	if e != nil {
		return e
	}
	return issueAuthenticated(c, root, raw, publicBase, out)
}

// issueAuthenticated is called only after protectedPolicy authenticates the
// root-owned policy. Tests exercise it with explicit PUBLIC TEST-ONLY policies.
func issueAuthenticated(c config, root *os.Root, raw []byte, publicBase string, out io.Writer) error {
	var in issuanceInput
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF {
		return fmt.Errorf("closed issuance policy invalid")
	}
	p := in.Policy
	if p.Purpose != "production" && p.Purpose != "rehearsal" {
		return fmt.Errorf("issuance purpose invalid")
	}
	if p.Claims.KeyID != c.keyID || ((p.Purpose == "rehearsal") != (c.keyID == releasefeedissuer.RehearsalKeyID)) {
		return fmt.Errorf("custodian purpose/key differs from policy")
	}
	if p.Purpose == "production" && p.Claims.Sequence <= 140 {
		return fmt.Errorf("production first entry must follow0140 rehearsal and contain PR326")
	}
	files, receipt, e := readIssueInputs(in)
	if e != nil {
		return e
	}
	for _, path := range []string{publicBase, filepath.Join(publicBase, "entries"), filepath.Join(publicBase, "trust"), filepath.Join(publicBase, "rehearsal")} {
		if e := releasefeedissuer.CheckPublicDirectory(path, c.uid); e != nil {
			return e
		}
	}
	// A durable whole-issuer lock precedes enumeration, per-sequence intent and
	// key read. Every failure retains it for original-operation reconciliation.
	if e := exclusive(root, "issuance.lock", []byte("fixed issue operation\n")); e != nil {
		return e
	}
	dir, e := root.Open(".")
	if e != nil {
		return e
	}
	entries, e := dir.ReadDir(-1)
	dir.Close()
	if e != nil {
		return e
	}
	pattern := regexp.MustCompile(`^sequence-([0-9]{6})\.intent\.json$`)
	for _, entry := range entries {
		m := pattern.FindStringSubmatch(entry.Name())
		if m != nil {
			n, _ := strconv.ParseUint(m[1], 10, 64)
			if p.Claims.Sequence <= n {
				return fmt.Errorf("sequence does not advance retained original intents")
			}
		}
	}
	h := sha256.Sum256(raw)
	intent, _ := json.Marshal(map[string]any{"schema": "pomar.feed-issue-intent/v1", "sequence": p.Claims.Sequence, "purpose": p.Purpose, "policy_sha256": hex.EncodeToString(h[:]), "key_id": c.keyID})
	stem := fmt.Sprintf("sequence-%06d", p.Claims.Sequence)
	if e := exclusive(root, stem+".intent.json", intent); e != nil {
		return e
	}
	var pub bytes.Buffer
	if e := public(c, root, &pub); e != nil {
		return e
	}
	seed, e := privateSeed(c, root)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	bundle, e := releasefeedissuer.Build(p, receipt, files, key, time.Now().UTC())
	if e != nil {
		return e
	}
	if e := exclusive(root, stem+".signed.attestation", bundle.Files["attestation.bin"]); e != nil {
		return e
	}
	if e := releasefeedissuer.Publish(publicBase, c.uid, bundle); e != nil {
		return e
	}
	done, _ := json.Marshal(map[string]any{"schema": "pomar.feed-issue-complete/v1", "entry_id": bundle.EntryID, "purpose": bundle.Purpose, "policy_sha256": hex.EncodeToString(h[:]), "at": time.Now().UTC().Format(time.RFC3339)})
	if e := exclusive(root, stem+".complete.json", done); e != nil {
		return e
	}
	if e := root.Remove("issuance.lock"); e != nil {
		return e
	}
	if e := syncHome(root); e != nil {
		return e
	}
	_, e = fmt.Fprintln(out, string(done))
	return e
}
