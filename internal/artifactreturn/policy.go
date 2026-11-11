// Package artifactreturn validates an explicit owner policy and receives named
// artifacts against the original signed Pomar result. It grants no admission.
package artifactreturn

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	MaxAggregateBytes  int64 = 1 << 30
	MaxFiles                 = 16
	MaxTransferSeconds       = 600
	MaxResultBytes           = 2 << 20
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var shaRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var imageRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Policy is supplied by the protected class and included in its signed result.
// Callers cannot select these limits. A provisional policy is permitted only
// for the initial measured build; it is never evidence of measured sizing.
type Policy struct {
	PerFileBytes         int64    `json:"per_file_bytes"`
	MaxFiles             int      `json:"max_files"`
	TransferSeconds      int      `json:"transfer_seconds"`
	Names                []string `json:"names"`
	Provisional          bool     `json:"provisional"`
	MeasuredBytes        int64    `json:"measured_bytes"`
	MarginBytes          int64    `json:"margin_bytes"`
	MeasurementAttempt   string   `json:"measurement_attempt,omitempty"`
	MeasurementResultSHA string   `json:"measurement_result_sha256,omitempty"`
}

func ValidName(name string) bool {
	return nameRE.MatchString(name) && !strings.Contains(name, "..")
}

// Validate never changes the historical report limit: an absent policy is
// not artifact permission. Aggregate is the class's OutputCapBytes.
func (p *Policy) Validate(aggregate int64) error {
	if p == nil || aggregate <= 0 || aggregate > MaxAggregateBytes ||
		p.PerFileBytes <= 0 || p.PerFileBytes > aggregate ||
		p.MaxFiles < 1 || p.MaxFiles > MaxFiles || len(p.Names) < 1 || len(p.Names) > p.MaxFiles ||
		p.TransferSeconds < 1 || p.TransferSeconds > MaxTransferSeconds {
		return fmt.Errorf("artifact: invalid explicit limits")
	}
	seen := map[string]bool{}
	for _, name := range p.Names {
		key := strings.ToLower(name)
		if !ValidName(name) || seen[key] || key == "original-result.json" || key == "ready.json" || key == "failed.json" {
			return fmt.Errorf("artifact: unsafe, repeated or case-alias output name")
		}
		seen[key] = true
	}
	if p.Provisional {
		if p.MeasuredBytes != 0 || p.MarginBytes != 0 || p.MeasurementAttempt != "" || p.MeasurementResultSHA != "" {
			return fmt.Errorf("artifact: provisional limit cannot claim a measurement")
		}
	} else if p.MeasuredBytes <= 0 || p.MarginBytes < 0 || p.MeasuredBytes > aggregate ||
		p.MarginBytes != aggregate-p.MeasuredBytes || !ValidName(p.MeasurementAttempt) ||
		!shaRE.MatchString(p.MeasurementResultSHA) {
		return fmt.Errorf("artifact: cap requires measured bytes, stated margin and original result binding")
	}
	return nil
}
