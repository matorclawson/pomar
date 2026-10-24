package nativeattestation

// sow: pomar-SOW-90
import (
	"crypto/ed25519"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/result"
)

const PolicySchema = "pomar.native-policy/v1"
const ProfRodRecipe = "profrod-hetzner-ci/v1"
const ContinuousClock = "mach_continuous_time/v1"
const ProfRodRepository = "https://github.com/rodriveracom/profrod-site.git"

type Output struct {
	Name     string `json:"name"`
	MaxBytes int64  `json:"max_bytes"`
}

// Policy is selected by the protected owner, pinned independently by consumers.
// It is not accepted as a job input. This slice defines just the fixed ProfRod
// release recipe, not an arbitrary command class or a runtime policy registry.
type Policy struct {
	Schema            string    `json:"schema"`
	ID                string    `json:"id"`
	Generation        string    `json:"generation"`
	ValidFrom         time.Time `json:"valid_from"`
	ValidUntil        time.Time `json:"valid_until"`
	Source            Source    `json:"source"`
	Recipe            string    `json:"recipe"`
	Argv              []string  `json:"argv"`
	EnvironmentSHA256 string    `json:"environment_sha256"`
	ToolClosureSHA256 string    `json:"tool_closure_sha256"`
	Tools             []Tool    `json:"tools"`
	Platform          Platform  `json:"platform"`
	Producer          Producer  `json:"producer"`
	Caller            string    `json:"caller"`
	CallerUID         int       `json:"caller_uid"`
	Inputs            []File    `json:"inputs"`
	Outputs           []Output  `json:"outputs"`
	MaxLogBytes       int64     `json:"max_log_bytes"`
	MaxArtifactBytes  int64     `json:"max_artifact_bytes"`
	MaxReturnBytes    int64     `json:"max_return_bytes"`
}

func hexID(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func text(s string) bool {
	return len(s) > 0 && len(s) <= 1024 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

func name(s string) bool {
	return text(s) && len(s) <= 128 && path.Base(s) == s && s != "." && s != ".." && !strings.Contains(s, "\\")
}

func absolute(s string) bool { return text(s) && path.IsAbs(s) && path.Clean(s) == s }

func files(fs []File) bool {
	if len(fs) > 64 {
		return false
	}
	previous := ""
	for _, f := range fs {
		if !name(f.Name) || f.Name <= previous || f.Bytes < 0 || !hexID(f.SHA256, 64) {
			return false
		}
		previous = f.Name
	}
	return true
}

func (p Policy) Validate() error {
	bad := func(why string) error { return fmt.Errorf("%w: policy %s", ErrInvalid, why) }
	if p.Schema != PolicySchema || !name(p.ID) || !text(p.Generation) || p.ValidFrom.IsZero() || !p.ValidFrom.Before(p.ValidUntil) {
		return bad("identity/validity")
	}
	s := p.Source
	if s.Repository != ProfRodRepository || s.Ref != "refs/heads/main" || !s.Clean || !hexID(s.Commit, 40) || !hexID(s.Tree, 40) || !hexID(s.ManifestSHA256, 64) {
		return bad("source")
	}
	if p.Recipe != ProfRodRecipe || len(p.Argv) != 3 || !absolute(p.Argv[0]) || p.Argv[1] != "--no-print-directory" || p.Argv[2] != "hetzner-ci" {
		return bad("fixed recipe")
	}
	if !hexID(p.EnvironmentSHA256, 64) || !hexID(p.ToolClosureSHA256, 64) || len(p.Tools) == 0 || len(p.Tools) > 64 {
		return bad("tool closure")
	}
	previous, makeFound := "", false
	for _, t := range p.Tools {
		if !name(t.Name) || t.Name <= previous || !absolute(t.Path) || !hexID(t.SHA256, 64) {
			return bad("tool")
		}
		if t.Name == "make" && t.Path == p.Argv[0] {
			makeFound = true
		}
		previous = t.Name
	}
	if !makeFound {
		return bad("recipe executable pin")
	}
	if p.Platform.OS != "darwin" || p.Platform.Architecture != "arm64" || !text(p.Platform.Version) || !text(p.Platform.Build) {
		return bad("native platform")
	}
	w := p.Producer
	if !name(w.Principal) || w.UID <= 0 || w.UID >= result.FirstRegularUID || !text(w.Observer) || !text(w.ObserverVersion) || !hexID(w.SigningKeyID, 64) || w.SigningPurpose != Schema {
		return bad("protected producer/purpose")
	}
	if !name(p.Caller) || p.CallerUID < result.FirstRegularUID {
		return bad("caller")
	}
	if len(p.Inputs) != 2 || !files(p.Inputs) || p.Inputs[0].Name != "opportunity-sources.json" || p.Inputs[1].Name != "public-config.json" {
		return bad("fixed inputs")
	}
	if p.Inputs[0].Bytes <= 0 || p.Inputs[0].Bytes > 24*1024*1024 || p.Inputs[1].Bytes <= 0 || p.Inputs[1].Bytes > 8*1024*1024 {
		return bad("input bounds")
	}
	if len(p.Outputs) != 1 || p.Outputs[0].Name != "release.json.gz" || p.Outputs[0].MaxBytes <= 0 || p.Outputs[0].MaxBytes > 320*1024*1024 {
		return bad("fixed output")
	}
	if p.MaxLogBytes <= 0 || p.MaxLogBytes > 64*1024*1024 || p.MaxArtifactBytes < p.Outputs[0].MaxBytes || p.MaxArtifactBytes > 320*1024*1024 || p.MaxReturnBytes <= 0 || p.MaxReturnBytes > 512*1024*1024 {
		return bad("return bounds")
	}
	if b, err := result.Canonical(p); err != nil || len(b) > MaxDocumentBytes {
		return bad("encoding bound")
	}
	return nil
}

func (p Policy) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	b, err := result.Canonical(p)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

func (p Policy) checkOriginal(o Original, now time.Time) error {
	if !name(o.ID) || !text(o.Incarnation) || !hexID(o.AdmissionSHA256, 64) || !hexID(o.JournalSHA256, 64) || !hexID(o.BootID, 64) || !text(o.CallerBirth) || o.CallerPID <= 1 || o.Caller != p.Caller || o.CallerUID != p.CallerUID || o.Clock != ContinuousClock || o.OriginTick == 0 || o.DeadlineTick <= o.OriginTick {
		return fmt.Errorf("%w: original identity", ErrInvalid)
	}
	argv, err := result.Canonical(p.Argv)
	if err != nil || o.CommandSHA256 != digest(argv) || o.Origin.IsZero() || !o.Origin.Before(o.Deadline) || now.IsZero() || now.Before(o.Origin) || !now.Before(o.Deadline) || o.Origin.Before(p.ValidFrom) || o.Deadline.After(p.ValidUntil) {
		return fmt.Errorf("%w: original command/validity", ErrInvalid)
	}
	return nil
}

func (p Policy) Check(proof Proof, original Original, now time.Time) error {
	policyID, err := p.Digest()
	if err != nil {
		return err
	}
	if err := p.checkOriginal(original, now); err != nil {
		return err
	}
	if proof.Schema != Schema || proof.PolicySHA256 != policyID || !equalOriginal(proof.Original, original) || proof.Source != p.Source || proof.Recipe != p.Recipe || !equalSlice(proof.Argv, p.Argv) || proof.EnvironmentSHA256 != p.EnvironmentSHA256 || proof.ToolClosureSHA256 != p.ToolClosureSHA256 || !equalSlice(proof.Tools, p.Tools) || proof.Platform != p.Platform || proof.Producer != p.Producer || !equalSlice(proof.Inputs, p.Inputs) {
		return fmt.Errorf("%w: policy/original binding", ErrInvalid)
	}
	if proof.State != "exited" || proof.ExitCode != 0 {
		return fmt.Errorf("%w: unsuccessful execution", ErrInvalid)
	}
	x := proof.Lifecycle
	if x.PID <= 1 || x.BirthSeconds == 0 || x.BirthMicros >= 1000000 || !hexID(x.ExecutableSHA256, 64) || !x.Waited || !x.StreamsComplete || !x.ArtifactsComplete || !x.CleanupComplete || !x.JournalDurable || !hexID(x.CleanupSHA256, 64) {
		return fmt.Errorf("%w: incomplete native custody", ErrInvalid)
	}
	for _, tool := range p.Tools {
		if tool.Name == "make" && x.ExecutableSHA256 != tool.SHA256 {
			return fmt.Errorf("%w: native executable", ErrInvalid)
		}
	}
	times := []time.Time{original.Origin, x.Start, x.NativeEnd, x.Wait, x.Cleanup, x.Frozen, now}
	for i := 1; i < len(times); i++ {
		if times[i].IsZero() || times[i].Before(times[i-1]) {
			return fmt.Errorf("%w: native time order", ErrInvalid)
		}
	}
	ticks := []uint64{original.OriginTick, x.StartTick, x.EndTick, x.WaitTick, x.CleanupTick, x.FrozenTick}
	for i := 1; i < len(ticks); i++ {
		if ticks[i] < ticks[i-1] || ticks[i] >= original.DeadlineTick {
			return fmt.Errorf("%w: native clock order", ErrInvalid)
		}
	}
	if proof.Stdout.Name != "stdout" || proof.Stderr.Name != "stderr" || !files([]File{proof.Stderr, proof.Stdout}) || proof.Stdout.Bytes > p.MaxLogBytes || proof.Stderr.Bytes > p.MaxLogBytes-proof.Stdout.Bytes {
		return fmt.Errorf("%w: log evidence", ErrInvalid)
	}
	if len(proof.Artifacts) != 1 || !files(proof.Artifacts) || proof.Artifacts[0].Name != p.Outputs[0].Name || proof.Artifacts[0].Bytes <= 0 || proof.Artifacts[0].Bytes > p.Outputs[0].MaxBytes || proof.Artifacts[0].Bytes > p.MaxArtifactBytes {
		return fmt.Errorf("%w: artifact evidence", ErrInvalid)
	}
	doc, err := Canonical(proof)
	controlBytes := int64(len(doc) + ed25519.SignatureSize)
	if err != nil || controlBytes > p.MaxReturnBytes || proof.Stdout.Bytes > p.MaxReturnBytes-controlBytes || proof.Stderr.Bytes > p.MaxReturnBytes-controlBytes-proof.Stdout.Bytes || proof.Artifacts[0].Bytes > p.MaxReturnBytes-controlBytes-proof.Stdout.Bytes-proof.Stderr.Bytes {
		return fmt.Errorf("%w: total return bound", ErrInvalid)
	}
	return nil
}

func equalSlice[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalOriginal(a, b Original) bool {
	// Strip in-memory monotonic annotations; durable journal/wire times are UTC.
	a.Origin, a.Deadline = a.Origin.UTC(), a.Deadline.UTC()
	b.Origin, b.Deadline = b.Origin.UTC(), b.Deadline.UTC()
	return a == b
}
