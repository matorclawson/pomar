package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/zeroemployeeorg/pomar/internal/artifactreturn"
	"io"
	"os"
	"syscall"
)

const artifactBindingSchema = "pomar.artifact-binding/v1"

type artifactBinding struct {
	Schema         string `json:"schema"`
	Attempt        string `json:"attempt"`
	Class          string `json:"class"`
	Mirror         string `json:"mirror"`
	Ref            string `json:"ref"`
	SourceSHA      string `json:"source_sha"`
	SourceGit      bool   `json:"source_git"`
	ReadOnlySource bool   `json:"readonly_source"`
	ImageDigest    string `json:"image_digest"`
	PackageSet     string `json:"package_set"`
	RootfsSHA256   string `json:"rootfs_sha256"`
	CommandSHA256  string `json:"command_sha256"`
	PolicySHA256   string `json:"policy_sha256"`
	KeyID          string `json:"key_id"`
	CallerUID      uint32 `json:"caller_uid"`
}

func decodeArtifactBinding(raw []byte) (artifactreturn.Expected, error) {
	var expected artifactreturn.Expected
	if len(raw) == 0 || len(raw) > 64<<10 {
		return expected, fmt.Errorf("artifact binding exceeds metadata limit")
	}
	keys := map[string]bool{}
	for _, k := range []string{"schema", "attempt", "class", "mirror", "ref", "source_sha", "source_git", "readonly_source", "image_digest", "package_set", "rootfs_sha256", "command_sha256", "policy_sha256", "key_id", "caller_uid"} {
		keys[k] = false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return expected, fmt.Errorf("artifact binding must be one object")
	}
	for dec.More() {
		token, err = dec.Token()
		if err != nil {
			return expected, err
		}
		key, ok := token.(string)
		seen, allowed := keys[key]
		if !ok || !allowed || seen {
			return expected, fmt.Errorf("artifact binding has unknown or duplicate field")
		}
		keys[key] = true
		var value json.RawMessage
		if err = dec.Decode(&value); err != nil {
			return expected, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return expected, fmt.Errorf("artifact binding cannot contain null fields")
		}
	}
	if token, err = dec.Token(); err != nil || token != json.Delim('}') {
		return expected, fmt.Errorf("artifact binding object end")
	}
	if _, err = dec.Token(); err != io.EOF {
		return expected, fmt.Errorf("artifact binding trailing data")
	}
	for _, seen := range keys {
		if !seen {
			return expected, fmt.Errorf("artifact binding missing explicit field")
		}
	}
	var binding artifactBinding
	if err = json.Unmarshal(raw, &binding); err != nil {
		return expected, err
	}
	if binding.Schema != artifactBindingSchema {
		return expected, fmt.Errorf("artifact binding schema")
	}
	return artifactreturn.Expected{Attempt: binding.Attempt, Class: binding.Class, Mirror: binding.Mirror, Ref: binding.Ref, SourceSHA: binding.SourceSHA, SourceGit: binding.SourceGit, ReadOnlySource: binding.ReadOnlySource, ImageDigest: binding.ImageDigest, PackageSet: binding.PackageSet, RootfsSHA256: binding.RootfsSHA256, CommandSHA256: binding.CommandSHA256, PolicySHA256: binding.PolicySHA256, KeyID: binding.KeyID, CallerUID: binding.CallerUID}, nil
}
func readArtifactBinding(path string) (artifactreturn.Expected, error) {
	var expected artifactreturn.Expected
	before, err := os.Lstat(path)
	if err != nil {
		return expected, err
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Size() > 64<<10 || owner.Nlink != 1 || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) {
		return expected, fmt.Errorf("artifact binding must be a bounded owner-controlled regular file")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return expected, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return expected, fmt.Errorf("artifact binding changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return expected, err
	}
	return decodeArtifactBinding(raw)
}
