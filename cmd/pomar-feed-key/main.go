// Command pomar-feed-key is the fixed ENG feed custodian operation designated
// by Architect on 2026-11-04. It has no path, identity or key-id overrides and
// provides no arbitrary-byte signing operation. Private seed bytes are confined
// to the designated custodian process and are never part of its output.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const custodyHome = "/Library/Application Support/pomar-feed"
const custodyKeyID = "pomar-feed-a-202611"

type config struct {
	home, host, keyID string
	publicBase        string
	uid, gid          int
	entropy           io.Reader
}

type publicRecord struct {
	Schema      string `json:"schema"`
	KeyID       string `json:"key_id"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"public_key_sha256"`
	Domain      string `json:"domain"`
	UID         int    `json:"custody_uid"`
	GID         int    `json:"custody_gid"`
	GeneratedAt string `json:"generated_at"`
	Status      string `json:"status"`
}

func main() {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		fmt.Fprintln(os.Stderr, "cannot disable core dumps")
		os.Exit(1)
	}
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "one fixed operation required: self-test-public, probe, generate, public, generate-rehearsal, public-rehearsal, issue-current, issue-rehearsal, publish-trust")
		os.Exit(2)
	}
	if os.Args[1] == "self-test-public" {
		if err := publicSelfTest(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "PUBLIC_SELF_TEST_PASS no_private_key_access=true")
		return
	}
	if os.Geteuid() != 530 || os.Getegid() != 530 {
		fmt.Fprintln(os.Stderr, "dedicated custodian UID530 GID530 required")
		os.Exit(1)
	}
	binding, err := loadSiteBinding()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	c := config{home: custodyHome, host: binding.Hostname, keyID: custodyKeyID, publicBase: binding.PublicBase, uid: 530, gid: 530, entropy: rand.Reader}
	if err := run(c, os.Args[1], os.Stdout); err != nil {
		// Errors are fixed words/metadata, never seed bytes or key objects.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func publicSelfTest() error {
	pub, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	sig, _ := hex.DecodeString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	if !ed25519.Verify(pub, nil, sig) || ed25519.Verify(pub, []byte{0}, sig) {
		return errors.New("public crypto self-test failed")
	}
	return nil
}

func run(c config, operation string, output io.Writer) error {
	host, err := os.Hostname()
	if err != nil || host != c.host {
		return errors.New("designated ENG host required")
	}
	if err := publicSelfTest(); err != nil {
		return err
	}
	if operation == "self-test-public" {
		_, err := fmt.Fprintln(output, "PUBLIC_SELF_TEST_PASS no_private_key_access=true")
		return err
	}
	rehearsal := operation == "generate-rehearsal" || operation == "public-rehearsal" || operation == "issue-rehearsal"
	if operation != "probe" && operation != "generate" && operation != "public" && operation != "issue-current" && operation != "publish-trust" && !rehearsal {
		return errors.New("unknown fixed operation")
	}
	if os.Geteuid() != c.uid || os.Getegid() != c.gid || c.uid == 0 {
		return errors.New("dedicated custodian UID530 GID530 required")
	}
	if operation == "probe" {
		return json.NewEncoder(output).Encode(map[string]any{"operation": "probe", "uid": os.Geteuid(), "gid": os.Getegid(), "host": host, "key_access": false})
	}
	if err := checkHome(c); err != nil {
		return err
	}
	if rehearsal {
		// Architect A1: a separate key never adopted by production trust.
		// The only extra path is this fixed child of the checked custody home.
		if operation == "generate-rehearsal" {
			if err := os.Mkdir(c.home+"/rehearsal", 0700); err != nil {
				return errors.New("rehearsal custody directory exists or unavailable; reconcile")
			}
			parent, err := os.Open(c.home)
			if err != nil {
				return errors.New("rehearsal parent sync unavailable")
			}
			err = parent.Sync()
			closeErr := parent.Close()
			if err != nil || closeErr != nil {
				return errors.New("rehearsal parent sync failed; preserve state")
			}
		}
		c.home += "/rehearsal"
		c.keyID = "pomar-feed-rehearsal-a-202611"
		if err := checkHome(c); err != nil {
			return err
		}
		if operation == "generate-rehearsal" {
			operation = "generate"
		} else if operation == "public-rehearsal" {
			operation = "public"
		}
	}
	root, err := os.OpenRoot(c.home)
	if err != nil {
		return errors.New("custody home unavailable")
	}
	defer root.Close()
	if operation == "generate" {
		return generate(c, root, output)
	}
	if operation == "publish-trust" {
		return publishTrust(c, root, c.publicBase, output)
	}
	if operation == "issue-current" || operation == "issue-rehearsal" {
		policy := "/Library/Application Support/pomar-feed-policy/current.json"
		if operation == "issue-rehearsal" {
			policy = "/Library/Application Support/pomar-feed-policy/rehearsal.json"
		}
		return issue(c, root, policy, c.publicBase, output)
	}
	return public(c, root, output)
}

func checkHome(c config) error {
	s, err := os.Lstat(c.home)
	if err != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return errors.New("custody home must be a real0700 directory")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != c.uid || int(st.Gid) != c.gid {
		return errors.New("custody home owner mismatch")
	}
	return noACL(c.home)
}

func noACL(path string) error {
	// Fixed platform metadata inspection; never opens file contents.
	cmd := exec.Command("/bin/ls", "-lde", path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	raw, err := cmd.Output()
	if err != nil || len(strings.Split(strings.TrimSpace(string(raw)), "\n")) != 1 {
		return errors.New("custody ACL absent-state not verified")
	}
	return nil
}

func syncHome(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func exclusive(root *os.Root, name string, raw []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("existing or unavailable custody object; preserve and reconcile")
	}
	defer f.Close()
	n, err := f.Write(raw)
	if err != nil || n != len(raw) {
		return errors.New("custody object incomplete; preserve state")
	}
	if err := f.Sync(); err != nil {
		return errors.New("custody object sync failed; preserve state")
	}
	if err := f.Close(); err != nil {
		return errors.New("custody object close failed; preserve state")
	}
	return syncHome(root)
}

func generate(c config, root *os.Root, output io.Writer) error {
	// Intent precedes entropy/key effects. Any uncertain predecessor refuses reuse.
	intent, _ := json.Marshal(map[string]any{"schema": "pomar.feed-key-intent/v1", "key_id": c.keyID, "uid": c.uid, "gid": c.gid, "at": time.Now().UTC().Format(time.RFC3339)})
	if err := exclusive(root, "generation.intent.json", intent); err != nil {
		return err
	}
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, err := io.ReadFull(c.entropy, seed); err != nil {
		return errors.New("entropy unavailable; intent retained")
	}
	if err := exclusive(root, "ed25519.seed", seed); err != nil {
		return err
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	pub := key.Public().(ed25519.PublicKey)
	fp := sha256.Sum256(pub)
	record := publicRecord{"pomar.feed-public-key/v1", c.keyID, "Ed25519", base64.StdEncoding.EncodeToString(pub), hex.EncodeToString(fp[:]), "pomar-release-entry-v1", c.uid, c.gid, time.Now().UTC().Format(time.RFC3339), "PUBLIC_NOT_YET_TRUST_ADOPTED"}
	raw, err := json.Marshal(record)
	if err != nil {
		return errors.New("public record encoding failed")
	}
	if err := exclusive(root, "public-key.json", raw); err != nil {
		return err
	}
	// Verify persisted seed/public binding before exposing successful public output.
	return public(c, root, output)
}

func privateSeed(c config, root *os.Root) ([]byte, error) {
	before, err := root.Lstat("ed25519.seed")
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("custody seed must be a regular leaf")
	}
	f, err := root.OpenFile("ed25519.seed", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("custody seed unavailable; preserve state")
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !os.SameFile(before, s) || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Size() != ed25519.SeedSize {
		return nil, errors.New("custody seed metadata mismatch")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != c.uid || int(st.Gid) != c.gid || st.Nlink != 1 {
		return nil, errors.New("custody seed identity mismatch")
	}
	if err := noACL(c.home + "/ed25519.seed"); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, ed25519.SeedSize+1))
	if err != nil || len(raw) != ed25519.SeedSize {
		clear(raw)
		return nil, errors.New("custody seed read incomplete")
	}
	return raw, nil
}

func public(c config, root *os.Root, output io.Writer) error {
	before, err := root.Lstat("public-key.json")
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("public completion must be a regular leaf")
	}
	f, err := root.OpenFile("public-key.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("public completion unavailable; preserve state")
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !os.SameFile(before, s) || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Size() > 8192 {
		return errors.New("public completion invalid")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != c.uid || int(st.Gid) != c.gid || st.Nlink != 1 {
		return errors.New("public completion identity mismatch")
	}
	if err := noACL(c.home + "/public-key.json"); err != nil {
		return err
	}
	var record publicRecord
	dec := json.NewDecoder(io.LimitReader(f, 8193))
	dec.DisallowUnknownFields()
	if dec.Decode(&record) != nil || dec.Decode(new(any)) != io.EOF || record.KeyID != c.keyID || record.UID != c.uid || record.GID != c.gid || record.Schema != "pomar.feed-public-key/v1" || record.Domain != "pomar-release-entry-v1" || record.Algorithm != "Ed25519" {
		return errors.New("public completion binding mismatch")
	}
	seed, err := privateSeed(c, root)
	if err != nil {
		return err
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	pub := key.Public().(ed25519.PublicKey)
	fp := sha256.Sum256(pub)
	if record.PublicKey != base64.StdEncoding.EncodeToString(pub) || record.Fingerprint != hex.EncodeToString(fp[:]) {
		return errors.New("persisted public/private binding mismatch")
	}
	return json.NewEncoder(output).Encode(record)
}
