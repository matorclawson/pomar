package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/capacity"
	"github.com/zeroemployeeorg/pomar/internal/manager"
	"github.com/zeroemployeeorg/pomar/internal/venue"
)

type healthCheck struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type healthClass struct {
	Name     string             `json:"name"`
	Fits     *int               `json:"fits_current"`
	Failures []capacity.Failure `json:"failures"`
}

type healthReport struct {
	Schema        string         `json:"schema"`
	ObservedAt    time.Time      `json:"observed_at"`
	Evidence      string         `json:"evidence_kind"`
	Status        string         `json:"status"`
	Socket        string         `json:"socket"`
	ClientVersion string         `json:"client_version"`
	ClientSource  string         `json:"client_source"`
	Manager       healthCheck    `json:"manager"`
	ResultKey     healthCheck    `json:"result_key_binding"`
	KeyID         string         `json:"result_key_id,omitempty"`
	Admission     healthCheck    `json:"admission"`
	Host          *capacity.Host `json:"configured_host_budget"`
	Space         *venue.Space   `json:"disk"`
	Live          *int           `json:"known_live_attempts"`
	Coverage      string         `json:"capacity_coverage"`
	Classes       []healthClass  `json:"caller_visible_classes"`
	Unknown       []string       `json:"unknown"`
	Next          []string       `json:"next_steps"`
}

// A single deadline covers both reads. No discovery, redirect, mutation, or
// privileged local-file inspection is part of a health observation.
func healthCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", os.Getenv("POMAR_SOCKET"), "approved manager socket")
	root := fs.String("root", "", "explicit manager owner root")
	machine := fs.Bool("json", false, "versioned machine-readable report")
	expected := fs.String("expected-key-id", "", "independently retained SHA256 of the result public key")
	deadline := fs.Duration("timeout", 8*time.Second, "total read deadline (100ms to 30s)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *deadline < 100*time.Millisecond || *deadline > 30*time.Second {
		fmt.Fprintln(stderr, "health: no positional arguments; timeout must be 100ms to 30s")
		return 2
	}
	if *expected != "" {
		b, err := hex.DecodeString(*expected)
		if err != nil || len(b) != sha256.Size {
			fmt.Fprintln(stderr, "health: expected-key-id must be a 64-digit public-key SHA256")
			return 2
		}
		*expected = strings.ToLower(*expected)
	}
	if explicitFlag(args, "root") && !explicitFlag(args, "socket") && *root != "" {
		*socket = manager.SocketPath(*root)
	}
	if *socket != "" && !filepath.IsAbs(*socket) {
		fmt.Fprintln(stderr, "health: socket must be absolute")
		return 2
	}
	r := healthReport{Schema: "pomar.health/v1", Evidence: "UNSIGNED_MANAGER_OBSERVATIONS", Socket: *socket,
		ClientVersion: version, ClientSource: sourceCommit, Classes: []healthClass{},
		Manager:   healthCheck{"NOT_SELECTED", "Select the approved manager with -socket or POMAR_SOCKET."},
		ResultKey: healthCheck{"UNKNOWN", "No public key observed."}, Admission: healthCheck{"UNKNOWN", "Current admission has not been observed."},
		Unknown: []string{"installed_service_release_and_code_signature", "physical_host_load_and_memory_pressure", "external_and_retained_environment_claims", "guest_and_helper_health", "end_to_end_signed_execution", "fleet_placement_and_queue_state"},
		Next:    []string{}}
	rc := 2
	if *socket != "" {
		ctx, cancel := context.WithTimeout(context.Background(), *deadline)
		defer cancel()
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", *socket)
		}}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		var raw struct {
			Host     *capacity.Host `json:"host"`
			Space    *venue.Space   `json:"space"`
			Live     *int           `json:"live"`
			Draining *bool          `json:"draining"`
			Coverage string         `json:"coverage"`
			Current  []struct {
				Name       string `json:"name"`
				Allocation *struct {
					Fits     *int               `json:"fits_current"`
					Failures []capacity.Failure `json:"failures"`
				} `json:"allocation"`
			} `json:"current"`
		}
		r.Manager = healthGET(ctx, client, "/v1/capacity", &raw)
		rc = 1
		if r.Manager.Status == "OBSERVED" {
			if raw.Host == nil || raw.Space == nil || raw.Live == nil || raw.Draining == nil || raw.Host.CPUSlots < 0 || raw.Host.MemoryBytes < 0 || raw.Space.Used < 0 || raw.Space.Avail < 0 || *raw.Live < 0 {
				r.Manager = healthCheck{"INVALID_REPLY", "Required capacity fields are absent or invalid."}
			} else {
				rc = 0
				r.Manager = healthCheck{"RESPONSIVE", "Authorized capacity API answered; guest execution is not tested."}
				r.Host, r.Space, r.Live, r.Coverage = raw.Host, raw.Space, raw.Live, raw.Coverage
				validCurrent := len(raw.Current) > 0 && raw.Coverage != ""
				fits := false
				seen := map[string]bool{}
				for _, row := range raw.Current {
					if row.Name == "" || seen[row.Name] || row.Allocation == nil || row.Allocation.Fits == nil || *row.Allocation.Fits < 0 {
						validCurrent = false
						break
					}
					seen[row.Name] = true
					if *row.Allocation.Fits > 0 {
						fits = true
					}
					failures := row.Allocation.Failures
					if failures == nil {
						failures = []capacity.Failure{}
					}
					r.Classes = append(r.Classes, healthClass{row.Name, row.Allocation.Fits, failures})
				}
				if !validCurrent {
					r.Classes = []healthClass{}
				}
				switch {
				case *raw.Draining:
					r.Admission = healthCheck{"DRAINING", "Owner admission fence is set; existing jobs may finish."}
				case !validCurrent:
					r.Admission = healthCheck{"UNKNOWN", "Manager does not expose a complete current-fit snapshot; idle fit is not current room."}
				case fits:
					r.Admission = healthCheck{"NUMERIC_FIT_OBSERVED", "A caller-visible class fits known claims; observation does not reserve or guarantee admission."}
				default:
					r.Admission = healthCheck{"NO_NUMERIC_FIT", "No caller-visible class fits this snapshot; inspect the typed deficits."}
				}
			}
		}
		var key manager.KeyReply
		r.ResultKey = healthGET(ctx, client, "/v1/signing-key", &key)
		if r.ResultKey.Status == "OBSERVED" {
			public, err := base64.StdEncoding.DecodeString(key.PublicKey)
			id := sha256.Sum256(public)
			if err != nil || key.Algorithm != "ed25519" || len(public) != ed25519.PublicKeySize || hex.EncodeToString(id[:]) != key.KeyID {
				r.ResultKey = healthCheck{"INVALID_REPLY", "Result public key and its reported ID do not agree."}
				rc = 1
			} else {
				r.KeyID = key.KeyID
				switch {
				case *expected == "":
					r.ResultKey = healthCheck{"UNPINNED", "Public key observed, but no independently retained expected ID supplied."}
				case key.KeyID != *expected:
					r.ResultKey = healthCheck{"MISMATCH", "Observed public key differs from the independently retained ID."}
					rc = 1
				default:
					r.ResultKey = healthCheck{"MATCH", "Public key bytes match the retained ID; this is not proof of endpoint possession or signed execution."}
				}
			}
		}
		if *expected != "" && r.ResultKey.Status != "MATCH" {
			rc = 1
		}
	}
	r.ObservedAt = time.Now().UTC()
	switch {
	case *socket == "":
		r.Status = "NOT_SELECTED"
	case rc != 0:
		r.Status = "ATTENTION"
	default:
		r.Status = "RESPONSIVE_WITH_UNKNOWNS"
	}
	r.Next = append(r.Next, "Use doctor for installed client/tool checks; health does not verify the installed daemon binary.")
	if r.Admission.Status == "UNKNOWN" {
		r.Unknown = append(r.Unknown, "current_admission_fit")
		r.Next = append(r.Next, "Obtain a current-capacity capable manager through the host owner's reviewed release path.")
	}
	if r.Admission.Status == "DRAINING" {
		r.Next = append(r.Next, "Ask the host owner about its drain window; do not automatically lift it.")
	}
	if r.ResultKey.Status == "UNPINNED" {
		r.Next = append(r.Next, "Supply -expected-key-id from the independently retained host binding, not this response.")
	}
	r.Next = append(r.Next, "Inspect a job with attempt progress -id ID; accept completion only after verifying its signed result.")
	if *machine {
		if json.NewEncoder(stdout).Encode(r) != nil {
			return 1
		}
	} else {
		printHealth(stdout, r)
	}
	return rc
}

func healthGET(ctx context.Context, client *http.Client, path string, out any) healthCheck {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://manager"+path, nil)
	if err != nil {
		return healthCheck{"UNAVAILABLE", "Cannot construct observation request."}
	}
	resp, err := client.Do(req)
	if err != nil {
		return healthCheck{"UNAVAILABLE", "Manager read failed or exceeded the total deadline; no state was changed."}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return healthCheck{fmt.Sprintf("HTTP_%d", resp.StatusCode), "Authorized route did not return a snapshot; no alternate socket was tried."}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return healthCheck{"INVALID_REPLY", "Response exceeded 1 MiB or could not be read."}
	}
	if len(b) == 0 || b[0] == 'n' || json.Unmarshal(b, out) != nil {
		return healthCheck{"INVALID_REPLY", "Response is not a valid observation object."}
	}
	return healthCheck{"OBSERVED", "Read-only API observation received."}
}

func printHealth(out io.Writer, r healthReport) {
	fmt.Fprintf(out, "Pomar: %s\nSocket: %s\nManager: %s — %s\nAdmission: %s — %s\nResult key: %s — %s\n", r.Status, r.Socket, r.Manager.Status, r.Manager.Detail, r.Admission.Status, r.Admission.Detail, r.ResultKey.Status, r.ResultKey.Detail)
	if r.Host != nil && r.Space != nil && r.Live != nil {
		fmt.Fprintf(out, "Budget: %d CPU slots, %.1f GiB memory; known live attempts: %d\nDisk: %.1f GiB available; coverage: %s\n", r.Host.CPUSlots, float64(r.Host.MemoryBytes)/(1<<30), *r.Live, float64(r.Space.Avail)/(1<<30), r.Coverage)
	}
	for i, c := range r.Classes {
		if i == 12 {
			fmt.Fprintln(out, "More class details are available with -json.")
			break
		}
		fmt.Fprintf(out, "Class %s: %d additional attempts fit known claims\n", c.Name, *c.Fits)
		for j, f := range c.Failures {
			if j == 4 {
				break
			}
			fmt.Fprintf(out, "  %s: deficit %d %s (demand %d, available %d)\n", f.Resource, f.Deficit, f.Unit, f.Demand, f.Available)
		}
	}
	fmt.Fprintln(out, "Not tested: installed service signature, host pressure, external claims, guest health, signed execution and fleet queue.")
	for _, s := range r.Next {
		fmt.Fprintln(out, "Next:", s)
	}
}
