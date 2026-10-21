package manager

// sow: pomar-SOW-87. This is trusted execution evidence, not release approval.
import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/capacity"
	"github.com/zeroemployeeorg/pomar/internal/proc"
	"github.com/zeroemployeeorg/pomar/internal/result"
	"github.com/zeroemployeeorg/pomar/internal/venue"
)

// ClosureDocument deliberately makes narrow positive claims: the owning VM
// helper acknowledged stop/delete; the owner observed the identified helper and
// linked VM service depart; the owned VM object has a durable removal record.
// It does not certify arbitrary native descendants or imported historical jobs.
type ClosureDocument struct {
	Schema             string         `json:"schema"`
	Attempt            string         `json:"attempt"`
	ResultSHA256       string         `json:"result_sha256"`
	Host               string         `json:"host"`
	Profile            string         `json:"execution_profile"`
	Lifecycle          string         `json:"lifecycle_version"`
	Class              capacity.Class `json:"class"`
	Pins               *Pins          `json:"pins"`
	ManagerVersion     string         `json:"closing_manager_version"`
	ManagerSHA256      string         `json:"closing_manager_sha256"`
	OwnerUID           int            `json:"owner_uid"`
	HelperPID          int            `json:"helper_pid"`
	HelperStart        string         `json:"helper_start"`
	VMPID              int            `json:"vm_pid"`
	VMStart            string         `json:"vm_start"`
	StopAcknowledged   bool           `json:"vm_stop_acknowledged"`
	DeleteAcknowledged bool           `json:"vm_delete_acknowledged"`
	HelperDeparture    bool           `json:"helper_departure_observed"`
	VMDeparture        bool           `json:"linked_vm_departure_observed"`
	OwnedObjectRemoved bool           `json:"owned_vm_object_removal_recorded"`
	ObservedAt         time.Time      `json:"observed_at"`
}

// Missing observations are retried briefly, then recorded as unavailable.
// This bound never expires an existing immutable publication intent.
const closureObservationWindow = 5 * time.Minute

func (m *Manager) closureObservation(e Entry, now time.Time) ([]byte, string) {
	if !validIntent(e) || e.Pins == nil || e.Pins.HostBin == "" {
		return nil, "original_binding_unknown"
	}
	status, err := result.ReadHelperStatus(filepath.Join(m.cfg.Venue.Root(), attemptsDir, e.Attempt))
	if errors.Is(err, result.ErrConflict) {
		return nil, "helper_cleanup_corrupt"
	}
	if err != nil {
		return nil, "helper_cleanup_unavailable"
	}
	var s map[string]string
	if json.Unmarshal(status, &s) != nil || s["attempt"] != e.Attempt || s["cleanup_schema"] != result.CleanupSchema || s["cleanup_helper_pid"] != strconv.Itoa(e.PID) {
		return nil, "helper_cleanup_binding_unknown"
	}
	if s["phase"] != "exited" && s["phase"] != "stopped" && s["phase"] != "failed" {
		return nil, "helper_cleanup_not_terminal"
	}
	if s["cleanup_stop_acknowledged"] != "true" || s["cleanup_delete_acknowledged"] != "true" || s["cleanup_stop_error"] != "" || s["cleanup_delete_error"] != "" {
		return nil, "helper_cleanup_not_acknowledged"
	}
	// Absence alone is never sufficient: require the positive acknowledgments
	// above, exact retained birth identities and the owned venue removal below.
	if e.PID <= 0 || e.Start == "" || e.Peaks.VMPID <= 0 || e.Peaks.VMStart == "" {
		return nil, "process_binding_unknown"
	}
	ps, err := m.cfg.Procs.List()
	if err != nil {
		return nil, "process_observation_unavailable"
	}
	if p, ok := proc.Find(ps, e.PID); ok && p.Start == e.Start {
		return nil, "helper_departure_pending"
	}
	if p, ok := proc.Find(ps, e.Peaks.VMPID); ok && p.Start == e.Peaks.VMStart {
		return nil, "linked_vm_departure_pending"
	}
	object, ok := m.cfg.Venue.ObjectState(venue.KindVM, e.Attempt)
	if !ok || object.Last != venue.OpRemoved || object.Created.IsZero() || object.Path != filepath.Join("store", "containers", e.Attempt) {
		return nil, "owned_vm_removal_unconfirmed"
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, "closing_manager_identity_unavailable"
	}
	hash, err := fileSHA256(executable)
	if err != nil {
		return nil, "closing_manager_identity_unavailable"
	}
	doc := ClosureDocument{Schema: result.ClosureSchema, Attempt: e.Attempt, ResultSHA256: e.Publication.Intent.SHA256, Host: e.ResultPolicy.KeyID, Profile: "linux-microvm/v1", Lifecycle: result.CleanupSchema, Class: e.Class, Pins: e.Pins, ManagerVersion: BuildVersion(), ManagerSHA256: hash, OwnerUID: m.cfg.UID, HelperPID: e.PID, HelperStart: e.Start, VMPID: e.Peaks.VMPID, VMStart: e.Peaks.VMStart, StopAcknowledged: true, DeleteAcknowledged: true, HelperDeparture: true, VMDeparture: true, OwnedObjectRemoved: true, ObservedAt: now.UTC()}
	b, err := result.Canonical(doc)
	if err != nil {
		return nil, "closure_document_invalid"
	}
	return b, ""
}

func validClosure(e Entry) bool {
	i := e.Closure.Intent
	if !e.ClosureRequired || !validIntent(e) || i == nil || i.Policy.Purpose != result.ClosureSchema || i.SHA256 != documentHash(i.Document) {
		return false
	}
	p := i.Policy
	p.Purpose = result.Schema
	if !validPolicy(p) || p.Mode != e.ResultPolicy.Mode || p.KeyID != e.ResultPolicy.KeyID || !bytes.Equal(p.PublicKey, e.ResultPolicy.PublicKey) {
		return false
	}
	var d ClosureDocument
	if json.Unmarshal(i.Document, &d) != nil || d.Schema != result.ClosureSchema || d.Attempt != e.Attempt || d.ResultSHA256 != e.Publication.Intent.SHA256 || d.Host != p.KeyID || d.Profile != "linux-microvm/v1" || d.Lifecycle != result.CleanupSchema || !d.StopAcknowledged || !d.DeleteAcknowledged || !d.HelperDeparture || !d.VMDeparture || !d.OwnedObjectRemoved || d.HelperPID != e.PID || d.HelperStart != e.Start || d.VMPID != e.Peaks.VMPID || d.VMStart != e.Peaks.VMStart || d.HelperPID <= 0 || d.HelperStart == "" || d.VMPID <= 0 || d.VMStart == "" || len(d.ManagerSHA256) != 64 || d.ManagerVersion == "" || d.ObservedAt.IsZero() {
		return false
	}
	a, _ := result.Canonical(d.Class)
	b, _ := result.Canonical(e.Class)
	x, _ := result.Canonical(d.Pins)
	y, _ := result.Canonical(e.Pins)
	canonical, err := result.Canonical(json.RawMessage(i.Document))
	return err == nil && bytes.Equal(canonical, i.Document) && bytes.Equal(a, b) && bytes.Equal(x, y)
}

// closurePair validates actual files against the original frozen intent. It
// never signs, reconstructs observations or treats a table marker as proof.
func (m *Manager) closurePair(e Entry) (ResultReply, int, string) {
	if !e.Terminal() {
		return ResultReply{}, 404, "no_closure"
	}
	if !e.ClosureRequired {
		return ResultReply{}, 409, "closure_unknown"
	}
	if e.Closure.State == "unavailable" {
		if !validUnavailableClosure(e) {
			return ResultReply{}, 409, "closure_corrupt"
		}
		if !e.closureSaved {
			return ResultReply{}, 503, "closure_pending"
		}
		return ResultReply{}, 409, "closure_unavailable"
	}
	if e.Closure.State == "corrupt" {
		return ResultReply{}, 409, "closure_corrupt"
	}
	if e.Closure.Intent == nil {
		return ResultReply{}, 503, "closure_held"
	}
	if !validClosure(e) {
		return ResultReply{}, 409, "closure_corrupt"
	}
	i := e.Closure.Intent
	doc, sig, err := result.ReadClosure(filepath.Join(m.cfg.Venue.Root(), attemptsDir, e.Attempt))
	if errors.Is(err, result.ErrConflict) {
		return ResultReply{}, 409, "closure_corrupt"
	}
	if err != nil {
		if e.Closure.State == "published" && errors.Is(err, os.ErrNotExist) {
			return ResultReply{}, 409, "closure_corrupt"
		}
		return ResultReply{}, 503, "closure_pending"
	}
	if !bytes.Equal(doc, i.Document) {
		return ResultReply{}, 409, "closure_corrupt"
	}
	out := ResultReply{Result: doc}
	if i.Policy.Mode == "signed" {
		if len(sig) == 0 {
			if e.Closure.State == "published" {
				return ResultReply{}, 409, "closure_corrupt"
			}
			return ResultReply{}, 503, "closure_pending"
		}
		if !result.VerifyClosure(i.Policy.PublicKey, doc, sig) {
			return ResultReply{}, 409, "closure_corrupt"
		}
		out.Signature = encodeSignature(sig)
		out.KeyID = i.Policy.KeyID
	} else if len(sig) != 0 {
		return ResultReply{}, 409, "closure_corrupt"
	}
	return out, 200, ""
}
func (m *Manager) closureRead(e Entry) (ResultReply, int, string) {
	out, status, code := m.closurePair(e)
	if status == 200 && (!e.closureSaved || e.Closure.State != "published") {
		return ResultReply{}, 503, "closure_pending"
	}
	return out, status, code
}

// recoverClosures is bounded and independent of the coding seats. Fresh
// observations run outside m.mu. A durable frozen intent is always saved before
// signing, so restart retries the SAME original statement and key, not the job.
func (m *Manager) recoverClosures(now time.Time) {
	m.mu.Lock()
	var work []Entry
	entries := m.t.list()
	start := m.closureCursor
	for off := 0; off < len(entries); off++ {
		idx := (start + off) % len(entries)
		e := entries[idx]
		if len(work) >= 16 {
			break
		}
		if e.Terminal() && e.ClosureRequired && e.Closure.State != "corrupt" && !((e.Closure.State == "published" || e.Closure.State == "unavailable") && e.closureSaved) && !now.Before(e.Closure.NextRetry) {
			work = append(work, e)
			m.closureCursor = (idx + 1) % len(entries)
		}
	}
	m.mu.Unlock()
	for _, snapshot := range work {
		var doc []byte
		var why string
		if snapshot.Closure.Intent == nil && snapshot.Closure.State != "unavailable" {
			doc, why = m.closureObservation(snapshot, now)
			if why != "" {
				// Unbound retained proof is conflict, not missing observations.
				// Keep it visible rather than aging it into a removable record.
				_, _, err := result.ReadClosure(filepath.Join(m.cfg.Venue.Root(), attemptsDir, snapshot.Attempt))
				if err == nil || errors.Is(err, result.ErrConflict) {
					why = "unbound_closure_evidence"
				}
			}
		}
		m.mu.Lock()
		e := m.t.entries[snapshot.Attempt]
		if e == nil || !e.Terminal() || e.Created != snapshot.Created || !e.ClosureRequired {
			m.mu.Unlock()
			continue
		}
		p := &e.Closure
		if p.State == "corrupt" || (p.State == "published" && e.closureSaved) {
			m.mu.Unlock()
			continue
		}
		if p.State == "unavailable" {
			// On restart, acknowledge the same disposition; do not observe again
			// or reset the deadline and hold the record forever.
			if !validUnavailableClosure(*e) {
				p.State, p.Error = "corrupt", "closure_disposition_invalid"
			}
			e.closureSaved = m.t.save() == nil
			m.mu.Unlock()
			continue
		}
		if p.Intent == nil && why != "" {
			if why == "helper_cleanup_corrupt" || why == "unbound_closure_evidence" {
				p.State, p.Error = "corrupt", why
			} else {
				if e.ClosureObservationDeadline.IsZero() {
					e.ClosureObservationDeadline = now.Add(closureObservationWindow)
				}
				p.State, p.Error = "held", why
				if !now.Before(e.ClosureObservationDeadline) {
					// No positive evidence was frozen. Unavailable is a negative
					// disposition, never a signed closure or custody release.
					p.State = "unavailable"
					p.NextRetry = time.Time{}
				} else {
					scheduleClosureRetry(p, now)
				}
			}
			e.closureSaved = m.t.save() == nil
			m.mu.Unlock()
			continue
		}
		if p.Intent == nil {
			policy := e.ResultPolicy
			policy.Purpose = result.ClosureSchema
			p.Intent = &CompletionIntent{Document: doc, SHA256: documentHash(doc), Policy: policy}
			p.State = "pending"
		}
		if !validClosure(*e) {
			p.State, p.Error = "corrupt", "closure_intent_invalid"
			_ = m.t.save()
			m.mu.Unlock()
			continue
		}
		if err := m.t.save(); err != nil {
			e.closureSaved = false
			m.mu.Unlock()
			continue
		}
		// Already complete original proof needs no current private key.
		out, status, _ := m.closurePair(*e)
		var err error
		if status == 200 {
			err = result.PublishClosure(filepath.Join(m.cfg.Venue.Root(), attemptsDir, e.Attempt), out.Result, decodeClosureSignature(out.Signature))
		} else if status == 409 {
			err = result.ErrConflict
		} else {
			var sig []byte
			policy := p.Intent.Policy
			if policy.Mode == "signed" {
				signer := m.cfg.Signer
				if signer == nil || signer.ID != policy.KeyID || !bytes.Equal(signer.Public(), policy.PublicKey) {
					p.State, p.Error = "held", "key_unavailable"
					scheduleClosureRetry(p, now)
					_ = m.t.save()
					m.mu.Unlock()
					continue
				}
				sig = signer.SignClosure(p.Intent.Document)
			}
			err = result.PublishClosure(filepath.Join(m.cfg.Venue.Root(), attemptsDir, e.Attempt), p.Intent.Document, sig)
		}
		if errors.Is(err, result.ErrConflict) {
			p.State, p.Error = "corrupt", "closure_conflict"
		} else if err != nil {
			p.State, p.Error = "pending", "storage_unavailable"
		} else {
			p.State, p.Error = "published", ""
		}
		scheduleClosureRetry(p, now)
		if p.State == "published" {
			p.NextRetry = time.Time{}
		}
		e.closureSaved = m.t.save() == nil
		m.mu.Unlock()
	}
}

func (m *Manager) closureRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/attempts/{id}/closure", m.attemptGuard(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID.MatchString(id) {
			reply(w, 400, map[string]string{"error": "invalid attempt id"})
			return
		}
		m.mu.Lock()
		e := m.t.entries[id]
		if e == nil {
			m.mu.Unlock()
			reply(w, 404, map[string]string{"error": "no_closure"})
			return
		}
		out, status, code := m.closureRead(*e)
		state, why := e.Closure.State, e.Closure.Error
		m.mu.Unlock()
		if status != 200 {
			if status == 503 {
				w.Header().Set("Retry-After", "1")
			}
			reply(w, status, map[string]any{"error": code, "closure_state": state, "reason_code": why, "retryable": status == 503})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		// Preserve the exact signed inner bytes, as for ResultReply.exact().
		w.Write(bytes.Replace(out.exact(), []byte(`{"result":`), []byte(`{"closure":`), 1))
	}))
}

func decodeClosureSignature(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }

// Repeated unavailable evidence is bounded work with capped backoff, rather
// than an unbounded per-second table rewrite or starvation of newer originals.
func scheduleClosureRetry(p *Publication, now time.Time) {
	if p.Attempts < ^uint32(0) {
		p.Attempts++
	}
	p.NextRetry = now.Add(min(60*time.Second, time.Second<<min(p.Attempts-1, 6)))
}

// Only absent observations may become unavailable. A frozen statement or a
// conflicting proof must keep its independent publication/recovery obligation.
func validUnavailableClosure(e Entry) bool {
	return e.ClosureRequired && e.Terminal() && e.Closure.State == "unavailable" &&
		e.Closure.Intent == nil && e.Closure.Error != "" && !e.ClosureObservationDeadline.IsZero()
}
