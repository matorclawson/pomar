package nativeattestation

// sow: pomar-SOW-90
import (
	"errors"
	"testing"
)

func TestPolicyDoesNotBecomeArbitraryCommandOrActorAuthority(t *testing.T) {
	policy, _, _, _, _ := fixture(t)
	changes := map[string]func(*Policy){
		"no-schema":            func(p *Policy) { p.Schema = "" },
		"no-expiry":            func(p *Policy) { p.ValidUntil = p.ValidFrom },
		"other-repo":           func(p *Policy) { p.Source.Repository = "https://github.com/foreign/other.git" },
		"other-ref":            func(p *Policy) { p.Source.Ref = "refs/heads/topic" },
		"uncommitted-source":   func(p *Policy) { p.Source.Commit = "" },
		"dirty":                func(p *Policy) { p.Source.Clean = false },
		"arbitrary-recipe":     func(p *Policy) { p.Recipe = "run-anything" },
		"ambient-executable":   func(p *Policy) { p.Argv[0] = "make" },
		"arbitrary-target":     func(p *Policy) { p.Argv[2] = "deploy" },
		"extra-argument":       func(p *Policy) { p.Argv = append(p.Argv, "--eval=anything") },
		"unbound-make":         func(p *Policy) { p.Tools[0].Path = "/other/make" },
		"missing-tool-closure": func(p *Policy) { p.ToolClosureSHA256 = "" },
		"missing-environment":  func(p *Policy) { p.EnvironmentSHA256 = "" },
		"duplicate-tool":       func(p *Policy) { p.Tools = append(p.Tools, p.Tools[0]) },
		"guest-platform":       func(p *Policy) { p.Platform.OS = "linux" },
		"wrong-architecture":   func(p *Policy) { p.Platform.Architecture = "amd64" },
		"root-signer":          func(p *Policy) { p.Producer.UID = 0 },
		"actor-signer":         func(p *Policy) { p.Producer.UID = 503 },
		"unbound-purpose":      func(p *Policy) { p.Producer.SigningPurpose = "pomar.result/v1" },
		"unbound-key":          func(p *Policy) { p.Producer.SigningKeyID = "" },
		"privileged-caller":    func(p *Policy) { p.CallerUID = 0 },
		"path-input":           func(p *Policy) { p.Inputs[0].Name = "../source" },
		"duplicate-input":      func(p *Policy) { p.Inputs[1] = p.Inputs[0] },
		"oversize-input":       func(p *Policy) { p.Inputs[0].Bytes = 24*1024*1024 + 1 },
		"other-output":         func(p *Policy) { p.Outputs[0].Name = "executable" },
		"unbounded-output":     func(p *Policy) { p.Outputs[0].MaxBytes = 0 },
		"oversize-output":      func(p *Policy) { p.Outputs[0].MaxBytes = 321 * 1024 * 1024 },
		"no-log-bound":         func(p *Policy) { p.MaxLogBytes = 0 },
		"negative-total":       func(p *Policy) { p.MaxReturnBytes = -1 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p := clonePolicy(t, policy)
			change(&p)
			if err := p.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe policy accepted", err)
			}
			if _, err := NewCollector(p); !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe policy got collector", err)
			}
		})
	}
}

func TestPolicyCapsIncludeControlDocumentAndBothRawStreams(t *testing.T) {
	policy, original, observed, now, _ := fixture(t)
	policy.MaxReturnBytes = 1
	id, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	observed.proof.PolicySHA256 = id
	if err := policy.Check(observed.proof, original, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("control document excluded from return bound", err)
	}
	policy, original, observed, now, _ = fixture(t)
	observed.proof.Stdout.Bytes = policy.MaxLogBytes
	observed.proof.Stderr.Bytes = 1
	if err := policy.Check(observed.proof, original, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("stderr escaped combined log cap", err)
	}
}
