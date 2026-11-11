package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/zeroemployeeorg/pomar/internal/capacity"
)

// A distinct verb prevents older helpers from silently ignoring artifact bounds.
func classHelperVerb(class capacity.Class) string {
	if class.ArtifactOutput != nil {
		return "artifact-helper-v1"
	}
	return "helper"
}

func classOutputArgs(rec string, names []string, class capacity.Class) []string {
	p := class.ArtifactOutput
	if p == nil {
		return outputArgs(rec, names, class.OutputCapBytes)
	}
	if p.Validate(class.OutputCapBytes) != nil || len(names) != len(p.Names) {
		return nil
	}
	return []string{"--outputs", strings.Join(names, ","), "--outputs-dir", filepath.Join(rec, outputsDir), "--outputs-max", strconv.FormatInt(class.OutputCapBytes, 10), "--artifact-output-per-file", strconv.FormatInt(p.PerFileBytes, 10), "--artifact-output-timeout", strconv.Itoa(p.TransferSeconds)}
}

func artifactOutputsComplete(outputs []OutputRecord, names []string) bool {
	if len(outputs) != len(names) {
		return false
	}
	want := map[string]bool{}
	for _, name := range names {
		want[name] = true
	}
	for _, o := range outputs {
		if !want[o.Name] || o.Status != OutputOK {
			return false
		}
		delete(want, o.Name)
	}
	return len(want) == 0
}

// Hash only an exclusive regular leaf produced by the bounded helper. Preserve
// failed bytes privately for reconciliation, never serve a partial artifact set.
func hashArtifact(path string, limit int64) (string, int64, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || owner.Nlink != 1 || owner.Uid != uint32(os.Geteuid()) || before.Size() > limit {
		return "", 0, fmt.Errorf("manager: unsafe artifact leaf")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", 0, fmt.Errorf("manager: artifact leaf changed")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", 0, err
	}
	after, err := f.Stat()
	if err != nil || n != before.Size() || n > limit || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", 0, fmt.Errorf("manager: artifact length or identity changed")
	}
	if err := f.Chmod(0o400); err != nil {
		return "", 0, err
	}
	if err := f.Sync(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func collectArtifactOutputs(rec string, names []string, class capacity.Class) []OutputRecord {
	out := make([]OutputRecord, 0, len(names))
	var total int64
	for _, name := range names {
		output := OutputRecord{Name: name, Status: OutputMissing}
		if class.ArtifactOutput != nil && class.ArtifactOutput.Validate(class.OutputCapBytes) == nil {
			limit := class.ArtifactOutput.PerFileBytes
			if limit > class.OutputCapBytes-total {
				limit = class.OutputCapBytes - total
			}
			sum, n, err := hashArtifact(filepath.Join(rec, outputsDir, name), limit)
			if err == nil {
				output.Status = OutputOK
				output.Bytes = n
				output.SHA256 = sum
				total += n
			}
		}
		out = append(out, output)
	}
	return out
}
