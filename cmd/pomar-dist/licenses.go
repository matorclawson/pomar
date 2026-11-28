package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const swiftLicenseTable = "SWIFTPM-LICENSES.tsv"

var packageIdentity = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
var swiftLicenseHeader = []string{"package", "version", "commit", "root_license_text", "sha256", "upstream_license"}

type swiftPin struct {
	Identity string
	Location string
	State    struct {
		Revision string
		Version  string
	}
}

type swiftLicense struct {
	swiftPin
	name   string
	digest string
	url    string
}

func swiftLicensePins(source string) ([]swiftLicense, error) {
	data, err := os.ReadFile(filepath.Join(source, "host", "Package.resolved"))
	if err != nil {
		return nil, err
	}
	var lock struct {
		Pins []swiftPin
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	data, err = os.ReadFile(filepath.Join(source, swiftLicenseTable))
	if err != nil {
		return nil, err
	}
	tsv := csv.NewReader(bytes.NewReader(data))
	tsv.Comma = '\t'
	rows, err := tsv.ReadAll()
	if err != nil || len(rows) == 0 || !slices.Equal(rows[0], swiftLicenseHeader) {
		return nil, fmt.Errorf("invalid SwiftPM license table")
	}
	pins := make(map[string]swiftPin, len(lock.Pins))
	for _, pin := range lock.Pins {
		if !packageIdentity.MatchString(pin.Identity) {
			return nil, fmt.Errorf("invalid SwiftPM package identity %q", pin.Identity)
		}
		if _, exists := pins[pin.Identity]; exists {
			return nil, fmt.Errorf("duplicate SwiftPM pin %s", pin.Identity)
		}
		pins[pin.Identity] = pin
	}
	var result []swiftLicense
	for _, row := range rows[1:] {
		pin, ok := pins[row[0]]
		if !ok || pin.State.Version != row[1] || pin.State.Revision != row[2] ||
			!regexpRevision.MatchString(row[2]) || row[3] == "" {
			return nil, fmt.Errorf("SwiftPM license row does not match lock pin %s", row[0])
		}
		sum, err := hex.DecodeString(row[4])
		if err != nil || len(sum) != sha256.Size || row[4] != strings.ToLower(row[4]) {
			return nil, fmt.Errorf("invalid SwiftPM license SHA256 for %s", pin.Identity)
		}
		repo, ok := strings.CutPrefix(strings.TrimSuffix(pin.Location, ".git"), "https://github.com/")
		name := path.Base(row[5])
		want := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", repo, row[2], name)
		if !ok || row[5] != want || !legalTextName(name) {
			return nil, fmt.Errorf("SwiftPM license URL does not match the pinned source of %s", pin.Identity)
		}
		delete(pins, pin.Identity)
		result = append(result, swiftLicense{pin, name, row[4], row[5]})
	}
	if len(pins) != 0 || len(result) == 0 {
		return nil, fmt.Errorf("SwiftPM license table must cover every locked package")
	}
	slices.SortFunc(result, func(a, b swiftLicense) int { return strings.Compare(a.Identity, b.Identity) })
	return result, nil
}

var regexpRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var legalFilename = regexp.MustCompile(`(?i)^(licen[cs]e|notices?|copying|copyright|unlicense)([-_.][a-z0-9]+)*$`)

func legalTextName(name string) bool {
	if !legalFilename.MatchString(name) {
		return false
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".go", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".sh", ".py", ".js", ".json", ".yml", ".yaml":
		return false
	}
	return true
}

func swiftGit(checkout string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", checkout}, args...)...)
	return cmd.Output()
}

// Collect exact upstream files from the resolved SwiftPM Git objects. No
// network access, mutable checkout file bytes or build paths enter the bundle.
func collectSwiftLicenses(source, checkouts string) ([]byte, error) {
	pins, err := swiftLicensePins(source)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("Pomar SwiftPM dependency licenses and notices\n")
	for _, pin := range pins {
		checkout := filepath.Join(checkouts, pin.Identity)
		if info, err := os.Lstat(checkout); err != nil || !info.IsDir() {
			return nil, fmt.Errorf("missing SwiftPM checkout for %s", pin.Identity)
		}
		head, err := swiftGit(checkout, "rev-parse", "HEAD")
		if err != nil || strings.TrimSpace(string(head)) != pin.State.Revision {
			return nil, fmt.Errorf("SwiftPM checkout revision differs for %s", pin.Identity)
		}
		dirty, err := swiftGit(checkout, "status", "--porcelain", "--untracked-files=all")
		if err != nil || len(dirty) != 0 {
			return nil, fmt.Errorf("SwiftPM checkout is dirty or unreadable for %s", pin.Identity)
		}
		files, err := swiftGit(checkout, "ls-tree", "-rz", pin.State.Revision)
		if err != nil {
			return nil, fmt.Errorf("cannot list pinned SwiftPM tree for %s: %w", pin.Identity, err)
		}
		fmt.Fprintf(&out, "\n===== %s %s (%s) =====\n%s\n", pin.Identity, pin.State.Version, pin.State.Revision, pin.url)
		found := false
		for _, entry := range bytes.Split(bytes.TrimSuffix(files, []byte{0}), []byte{0}) {
			metadata, name, ok := strings.Cut(string(entry), "\t")
			if !ok || !legalTextName(path.Base(name)) {
				continue
			}
			if !strings.HasPrefix(metadata, "100644 blob ") && !strings.HasPrefix(metadata, "100755 blob ") {
				return nil, fmt.Errorf("SwiftPM license is not a regular file: %s/%q", pin.Identity, name)
			}
			raw, err := swiftGit(checkout, "cat-file", "blob", pin.State.Revision+":"+name)
			if err != nil || len(raw) > 1<<20 {
				return nil, fmt.Errorf("SwiftPM license text unavailable or oversized: %s/%q", pin.Identity, name)
			}
			// An empty secondary file carries no license or notice text.
			// The pinned root must always contain its declared license.
			if len(raw) == 0 && name != pin.name {
				continue
			}
			if len(bytes.TrimSpace(raw)) == 0 {
				return nil, fmt.Errorf("SwiftPM license has no text: %s/%q", pin.Identity, name)
			}
			if name == pin.name {
				hash := sha256.Sum256(raw)
				if hex.EncodeToString(hash[:]) != pin.digest {
					return nil, fmt.Errorf("SwiftPM license digest differs for %s", pin.Identity)
				}
				found = true
			}
			fmt.Fprintf(&out, "\n--- %s/%s ---\n", pin.Identity, name)
			out.Write(raw)
			out.WriteByte('\n')
		}
		if !found {
			return nil, fmt.Errorf("pinned SwiftPM root license missing for %s", pin.Identity)
		}
	}
	return out.Bytes(), nil
}
