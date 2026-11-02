// Package prequal prepares and records an owner-controlled, pre-model
// disposable qualification. Its result never grants a seat launch or an
// interactive agent qualification.
package prequal

import (
	"errors"
	"path/filepath"
	"regexp"
	"time"
)

const PlanSchema = "pomar.pre-model-plan/v1"
const ResultSchema = "pomar.pre-model-observations/v1"

// These are the independently reviewed M1/M2/S1/S2 repaired probe pins.
const ProbeCommit = "c431ec15f2f23e417c98227919fd766ce51163de"
const ProbeSHA256 = "c6aad3b4cf6182297f90ec78aa072a6c658d5ef6e1821b5be1c3906552574bc3"

var id = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var sha = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commit = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Plan is deliberately not an agentenv.EnvironmentProfile or seatdecl.Compiled.
// Declaration/catalogue binding is made by the owning adapter; arbitrary
// guest JSON and a nonempty qualification string cannot create one.
type Plan struct {
	RegistryStore        string    `json:"registry_store"`
	RegisteredAt         string    `json:"registered_at"`
	RegistryRecordSHA256 string    `json:"registry_record_sha256"`
	Schema               string    `json:"schema"`
	Operation            string    `json:"operation"`
	Seat                 string    `json:"seat"`
	Environment          string    `json:"environment"`
	Session              string    `json:"session"`
	Incarnation          string    `json:"incarnation"`
	DeclarationSHA256    string    `json:"declaration_sha256"`
	CatalogueSHA256      string    `json:"catalogue_sha256"`
	ImageSHA256          string    `json:"image_sha256"`
	SourceCommit         string    `json:"source_commit"`
	AgentArchive         Artifact  `json:"agent_archive"`
	CPUs                 int       `json:"cpus"`
	MemoryGiB            int       `json:"memory_gib"`
	DiskGiB              int       `json:"disk_gib"`
	Deadline             time.Time `json:"original_deadline"`
	ProbeCommit          string    `json:"probe_commit"`
	Probe                Artifact  `json:"probe"`
	ProbePlan            Artifact  `json:"probe_plan"`
	Driver               Artifact  `json:"driver"`
	HostControlsSHA256   string    `json:"host_controls_sha256"`
}

func (p Plan) Validate(now time.Time) error {
	if !filepath.IsAbs(p.RegistryStore) || filepath.Clean(p.RegistryStore) != p.RegistryStore || !sha.MatchString(p.RegistryRecordSHA256) {
		return errors.New("actual canonical registry store and captured record digest required")
	}
	if _, e := time.Parse(time.RFC3339Nano, p.RegisteredAt); e != nil {
		return errors.New("actual registered_at required")
	}

	if p.Schema != PlanSchema || !id.MatchString(p.Operation) || !id.MatchString(p.Seat) || !id.MatchString(p.Environment) || !id.MatchString(p.Session) || !id.MatchString(p.Incarnation) {
		return errors.New("distinct pre-model schema and exact original identities required")
	}
	if !sha.MatchString(p.DeclarationSHA256) || !sha.MatchString(p.CatalogueSHA256) || !sha.MatchString(p.ImageSHA256) || !commit.MatchString(p.SourceCommit) || !sha.MatchString(p.HostControlsSHA256) {
		return errors.New("actual declaration/catalogue/image/source/host-control pins required")
	}
	if p.CPUs < 1 || p.CPUs > 4 || p.MemoryGiB < 1 || p.MemoryGiB > 8 || p.DiskGiB < 1 || p.DiskGiB > 64 || !p.Deadline.After(now) || p.Deadline.Sub(now) > 10*time.Minute {
		return errors.New("bounded resources and original live deadline at most ten minutes required")
	}
	if p.ProbeCommit != ProbeCommit || p.Probe.SHA256 != ProbeSHA256 {
		return errors.New("only the fixed repaired isolation probe may run")
	}
	for _, a := range []Artifact{p.AgentArchive, p.Probe, p.ProbePlan, p.Driver} {
		if !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path || !sha.MatchString(a.SHA256) {
			return errors.New("owner-selected canonical artifact paths and exact SHA256 required")
		}
	}
	return nil
}

// Registration is returned only by the owning registry adapter after claiming
// the exact fresh absent-name registrar operation for this qualification. Evidence hashes bind the real row and empty prior
// session/mail histories; an adapter must not infer these from a name or flags.
type Registration struct {
	Instance        string `json:"instance"`
	Store           string `json:"store"`
	RegisteredAt    string `json:"registered_at"`
	RecordSHA256    string `json:"record_sha256"`
	Runtime         string `json:"runtime"`
	WriteAuthority  string `json:"write_authority"`
	Status          string `json:"status"`
	Operation       string `json:"qualification_operation"`
	HistorySHA256   string `json:"history_sha256"`
	Preimage        string `json:"original_name_preimage"`
	EarlierSessions uint64 `json:"earlier_sessions"`
	EarlierMail     uint64 `json:"earlier_mail"`
}

func (r Registration) validate(p Plan) error {
	if r.Instance != p.Seat || r.Store != p.RegistryStore || r.RegisteredAt != p.RegisteredAt || r.RecordSHA256 != p.RegistryRecordSHA256 || r.Runtime != "pre-model-observer" || r.WriteAuthority != "none" || r.Status != "active" || r.Operation != p.Operation || !sha.MatchString(r.RecordSHA256) || !sha.MatchString(r.HistorySHA256) || r.Preimage != "absent" || r.EarlierSessions != 0 || r.EarlierMail != 0 {
		return errors.New("actual fresh disposable registration with no earlier seat/session/mail required")
	}
	return nil
}

// Retirement preserves split outcomes too: a row may be retired even when
// provisioning teardown failed. Status alone never proves process drain.
type Retirement struct {
	Instance              string `json:"instance"`
	Store                 string `json:"store"`
	RegisteredAt          string `json:"registered_at"`
	Operation             string `json:"qualification_operation"`
	Status                string `json:"status"`
	CommandTerminalSHA256 string `json:"command_terminal_sha256"`
	ReadbackSHA256        string `json:"readback_sha256"`
	TerminalExit          int    `json:"terminal_exit"`
	Teardown              string `json:"teardown"`
}
