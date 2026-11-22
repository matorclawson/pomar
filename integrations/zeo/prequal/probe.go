package prequal

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
)

type observer struct {
	UID    int   `json:"uid"`
	EUID   int   `json:"euid"`
	GID    int   `json:"gid"`
	EGID   int   `json:"egid"`
	Groups []int `json:"groups"`
}
type mounts struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	Base64 string `json:"base64"`
}

func (m *mounts) valid() bool {
	if m == nil || m.Bytes <= 0 || m.Bytes > 1<<20 {
		return false
	}
	b, e := base64.StdEncoding.DecodeString(m.Base64)
	h := sha256.Sum256(b)
	return e == nil && len(b) == m.Bytes && hex.EncodeToString(h[:]) == m.SHA256
}

// Validate the fixed probe's actual receipt binding, never an admission claim.
// Native resource existence/share comparison still belongs to the owner.
func probeObservation(raw []byte, p Plan) error {
	var r struct {
		Schema       string    `json:"schema"`
		State        string    `json:"state"`
		PlanSHA      string    `json:"plan_sha256"`
		Environment  string    `json:"environment"`
		Session      string    `json:"session"`
		Incarnation  string    `json:"incarnation"`
		Admission    *bool     `json:"admission_granted"`
		Accepted     *bool     `json:"native_isolation_accepted"`
		Before       *observer `json:"observed_before"`
		After        *observer `json:"observed_after"`
		MountsBefore *mounts   `json:"mountinfo_before"`
		MountsAfter  *mounts   `json:"mountinfo_after"`
		Observations []struct {
			State  string `json:"state"`
			Before bool   `json:"positive_before"`
			After  bool   `json:"positive_after"`
			Errno  string `json:"errno_class"`
			Owner  string `json:"owner_evidence_sha256"`
		} `json:"observations"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Schema != "pomar.isolation-probe/v2" || r.State != "observations_complete_requires_owner_join" || r.PlanSHA != p.ProbePlan.SHA256 || r.Environment != p.Environment || r.Session != p.Session || r.Incarnation != p.Incarnation || r.Admission == nil || *r.Admission || r.Accepted == nil || *r.Accepted || r.Before == nil || r.After == nil || r.Before.UID != 1000 || r.Before.EUID != 1000 || r.Before.GID != 1000 || r.Before.EGID != 1000 || r.Before.Groups == nil || !reflect.DeepEqual(r.Before, r.After) || !r.MountsBefore.valid() || !r.MountsAfter.valid() || r.MountsBefore.SHA256 != r.MountsAfter.SHA256 || len(r.Observations) == 0 {
		return errors.New("fixed repaired probe identity/mount/original receipt missing or mismatched")
	}
	for _, o := range r.Observations {
		if o.State != "refused_requires_owner_join" || !o.Before || !o.After || !sha.MatchString(o.Owner) || (o.Errno != "ENOENT" && o.Errno != "ENOTDIR" && o.Errno != "EACCES" && o.Errno != "EPERM") {
			return errors.New("paired native observation incomplete")
		}
	}
	return nil
}
