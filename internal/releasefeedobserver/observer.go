// Package releasefeedobserver records bounded release artifact observations.
// A receipt proves byte bindings only: it never invents a build qualification,
// grants signing authority, or independently attests an owner's deployment.
package releasefeedobserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

const MaxArtifactBytes = 32 << 20

var objectID = regexp.MustCompile(`^[0-9a-f]{40}$`)
var nameID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,199}$`)

type Context struct {
	Head, Tree, SourceOwnerMessage string
	ObservedAt                     time.Time
}
type Artifact struct {
	Name   string `json:"name"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type Receipt struct {
	Schema                          string     `json:"schema"`
	Repository                      string     `json:"repository"`
	Head                            string     `json:"head"`
	Tree                            string     `json:"tree"`
	Sequence                        uint64     `json:"sequence"`
	ObservedAt                      string     `json:"observed_at"`
	SourceOwnerMessage              string     `json:"source_owner_message"`
	BuildQualification              bool       `json:"build_qualification"`
	DeploymentIndependentlyObserved bool       `json:"deployment_independently_observed"`
	Files                           []Artifact `json:"files"`
}
type manifest struct {
	Schema     string `json:"schema"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Sequence   uint64 `json:"sequence"`
	Artifacts  map[string]struct {
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"artifacts"`
}

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// Observe receives immutable snapshots from the host adapter. Source head/tree
// and owner message must be independently received by that adapter. This pure
// function has no credentials, key access, filesystem writes or signing path.
func Observe(c Context, files map[string][]byte) ([]byte, error) {
	if !objectID.MatchString(c.Head) || !objectID.MatchString(c.Tree) || c.SourceOwnerMessage == "" || len(c.SourceOwnerMessage) > 256 || c.ObservedAt.IsZero() || c.ObservedAt.Year() < 1 || c.ObservedAt.Year() > 9999 {
		return nil, fmt.Errorf("observation context incomplete")
	}
	raw := files["release.json"]
	if len(raw) == 0 || len(raw) > 131072 {
		return nil, fmt.Errorf("manifest length invalid")
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(raw)), 0); err != nil {
		return nil, err
	}
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	if dec.Decode(&m) != nil || dec.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("manifest JSON invalid")
	}
	// This increment observes release/1 only. A later schema requires its own
	// artifact admission: unrecognized semantics cannot silently lose wheel pins.
	if m.Schema != "zeoconnect-release/1" || m.Repository != "rodriveracom/zeoconnect" || m.Commit != c.Head || m.Sequence < 1 || m.Sequence > 999999 || len(m.Artifacts) < 1 || len(m.Artifacts) > 16 {
		return nil, fmt.Errorf("manifest source or schema binding mismatch")
	}
	if len(files) != len(m.Artifacts)+2 {
		return nil, fmt.Errorf("unexpected or missing input files")
	}
	names := make([]string, 0, len(m.Artifacts))
	for n, p := range m.Artifacts {
		if !nameID.MatchString(n) || n == "release.json" || n == "SHA256SUMS" || p.Bytes < 1 || p.Bytes > MaxArtifactBytes {
			return nil, fmt.Errorf("artifact declaration invalid")
		}
		b, ok := files[n]
		if !ok || len(b) != p.Bytes || digest(b) != p.SHA256 {
			return nil, fmt.Errorf("artifact bytes differ: %s", n)
		}
		names = append(names, n)
	}
	sums := files["SHA256SUMS"]
	if len(sums) < 1 || len(sums) > 16384 {
		return nil, fmt.Errorf("checksum list invalid")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n") {
		pair := strings.Split(line, "  ")
		if len(pair) != 2 || seen[pair[1]] {
			return nil, fmt.Errorf("checksum list malformed or duplicate")
		}
		p, ok := m.Artifacts[pair[1]]
		if !ok || pair[0] != p.SHA256 {
			return nil, fmt.Errorf("checksum list differs")
		}
		seen[pair[1]] = true
	}
	if len(seen) != len(names) {
		return nil, fmt.Errorf("checksum list incomplete")
	}
	names = append(names, "release.json", "SHA256SUMS")
	sort.Strings(names)
	r := Receipt{Schema: "pomar.release-artifact-observation/v1", Repository: m.Repository, Head: c.Head, Tree: c.Tree, Sequence: m.Sequence, ObservedAt: c.ObservedAt.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z"), SourceOwnerMessage: c.SourceOwnerMessage}
	for _, n := range names {
		r.Files = append(r.Files, Artifact{n, len(files[n]), digest(files[n])})
	}
	return json.Marshal(r)
}

// Reject duplicate names at every level before normal decoding can collapse
// them. A byte observation must not admit conflicting interpretations.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting excessive")
	}
	tok, e := d.Token()
	if e != nil {
		return fmt.Errorf("JSON token invalid")
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return fmt.Errorf("JSON name invalid")
			}
			name, ok := k.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate JSON name")
			}
			seen[name] = true
			if e := uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return fmt.Errorf("JSON object incomplete")
		}
	case json.Delim('['):
		for d.More() {
			if e := uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return fmt.Errorf("JSON array incomplete")
		}
	}
	return nil
}
