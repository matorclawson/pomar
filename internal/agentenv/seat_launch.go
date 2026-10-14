package agentenv

import (
	"errors"
	"regexp"
)

// SeatLaunch is the declaration's explicit Codex policy, carried by the
// trusted profile into the VM. Credentials and arbitrary argv are not fields.
type SeatLaunch struct {
	Sandbox       string `json:"sandbox"`
	Approvals     string `json:"approvals"`
	NetworkAccess *bool  `json:"network_access"`
	Model         string `json:"model"`
	Effort        string `json:"effort"`
	CWD           string `json:"cwd"`
}

func (l *SeatLaunch) Validate() error {
	if l == nil || l.NetworkAccess == nil {
		return errors.New("Codex seat needs declared launch settings and explicit network access")
	}
	switch l.Sandbox {
	case "read-only", "workspace-write", "danger-full-access":
	default:
		return errors.New("unknown declared sandbox")
	}
	if l.Approvals != "never" && l.Approvals != "on-request" {
		return errors.New("unknown declared approval policy")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`).MatchString(l.Model) {
		return errors.New("declared model must be a bounded identifier")
	}
	switch l.Effort {
	case "medium", "high":
	default:
		return errors.New("unknown declared effort")
	}
	if l.CWD != "/work" {
		return errors.New("the current seat source materializer supports declared cwd /work only")
	}
	if l.Sandbox == "read-only" && *l.NetworkAccess {
		return errors.New("read-only cannot promise the workspace-write network override")
	}
	if l.Sandbox == "danger-full-access" && !*l.NetworkAccess {
		return errors.New("danger-full-access cannot promise a disabled tool network")
	}
	return nil
}
