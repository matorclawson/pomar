package manager

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"path/filepath"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/result"
)

// ResultPolicy is an admission fact. An absent policy is unknown, never an
// instruction to downgrade to unsigned when a key is missing after restart.
type ResultPolicy struct {
	Mode      string `json:"mode,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	PublicKey []byte `json:"public_key,omitempty"`
}

type CompletionIntent struct {
	Document []byte       `json:"document"` // exact canonical bytes; JSON encodes base64
	SHA256   string       `json:"sha256"`
	Policy   ResultPolicy `json:"policy"`
}

// Publication is independent of execution state: a failed execution can have a
// successfully published result. None of these states authorizes re-execution.
type Publication struct {
	Intent    *CompletionIntent `json:"intent,omitempty"`
	State     string            `json:"state,omitempty"`
	Error     string            `json:"error,omitempty"`
	Attempts  uint32            `json:"attempts,omitempty"`
	NextRetry time.Time         `json:"next_retry,omitzero"`
}

func documentHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (m *Manager) resultPolicy() ResultPolicy {
	if s := m.cfg.Signer; s != nil {
		return ResultPolicy{Mode: "signed", Purpose: result.Schema, KeyID: s.ID, PublicKey: bytes.Clone(s.Public())}
	}
	return ResultPolicy{Mode: "unsigned-development", Purpose: result.Schema}
}

func validPolicy(p ResultPolicy) bool {
	if p.Purpose != result.Schema {
		return false
	}
	if p.Mode == "unsigned-development" {
		return p.KeyID == "" && len(p.PublicKey) == 0
	}
	return p.Mode == "signed" && len(p.PublicKey) == 32 && result.KeyID(p.PublicKey) == p.KeyID
}

// freezeResult prepares trusted completion metadata; do not hold m.mu because
// mirror resolution may invoke git. Production finish supplies that metadata.
func (m *Manager) freezeResult(e *Entry) {
	m.freezeResultWithRepository(e, m.resultRepository(*e))
}

func (m *Manager) freezeResultWithRepository(e *Entry, repository string) {
	if !e.Terminal() || e.Publication.Intent != nil {
		return
	}
	if !validPolicy(e.ResultPolicy) {
		e.Publication = Publication{State: "unknown", Error: "completion_policy_unknown"}
		return
	}
	doc := m.resultDocWithRepository(*e, repository)
	doc["host"] = e.ResultPolicy.KeyID
	b, err := result.Canonical(doc)
	if err != nil || len(b) > 4<<20 {
		e.Publication = Publication{State: "corrupt", Error: "completion_document_invalid"}
		return
	}
	e.Publication = Publication{State: "pending", Intent: &CompletionIntent{Document: b, SHA256: documentHash(b), Policy: e.ResultPolicy}}
}

func validIntent(e Entry) bool {
	i := e.Publication.Intent
	if i == nil || !e.Terminal() || !validPolicy(i.Policy) || i.Policy.Mode != e.ResultPolicy.Mode || i.Policy.Purpose != e.ResultPolicy.Purpose || i.Policy.KeyID != e.ResultPolicy.KeyID || !bytes.Equal(i.Policy.PublicKey, e.ResultPolicy.PublicKey) || documentHash(i.Document) != i.SHA256 {
		return false
	}
	var d struct {
		Schema   string   `json:"schema"`
		Attempt  string   `json:"attempt"`
		State    State    `json:"state"`
		Host     string   `json:"host"`
		ExitCode *int     `json:"exit_code"`
		Command  []string `json:"command"`
	}
	if json.Unmarshal(i.Document, &d) != nil || d.Schema != result.Schema || d.Attempt != e.Attempt || d.State != e.State || d.Host != i.Policy.KeyID {
		return false
	}
	b, err := result.Canonical(json.RawMessage(i.Document))
	if err != nil || !bytes.Equal(b, i.Document) {
		return false
	}
	x, _ := json.Marshal(d.ExitCode)
	y, _ := json.Marshal(e.ExitCode)
	c, _ := json.Marshal(d.Command)
	v, _ := json.Marshal(e.Command)
	if !bytes.Equal(x, y) || !bytes.Equal(c, v) {
		return false
	}
	// Validate all retained execution metadata, without consulting current mirrors,
	// configuration, logs, artifacts or keys. The historical repository URL is
	// frozen in Document; it is not re-resolved as recovery authority.
	var fields map[string]json.RawMessage
	if json.Unmarshal(i.Document, &fields) != nil {
		return false
	}
	delete(fields, "repo")
	actual, err := result.Canonical(fields)
	if err != nil {
		return false
	}
	frozenView := (&Manager{}).resultDoc(e)
	frozenView["host"] = i.Policy.KeyID
	expected, err := result.Canonical(frozenView)
	return err == nil && bytes.Equal(actual, expected)
}

// publicationRead never signs or changes files. Readers validate actual bytes,
// not merely a persisted "published" marker. m.mu must be held.
func (m *Manager) publicationRead(e Entry) (ResultReply, int, string) {
	out := ResultReply{}
	if !e.Terminal() {
		return out, http.StatusNotFound, "no_result"
	}
	p := e.Publication
	if p.State == "corrupt" {
		return out, http.StatusConflict, "result_corrupt"
	}
	if p.State == "unknown" {
		return out, http.StatusConflict, "result_unknown"
	}
	if p.Intent != nil && !validIntent(e) {
		return out, http.StatusConflict, "result_corrupt"
	}
	doc, sig, err := result.Read(filepath.Join(m.cfg.Venue.Root(), attemptsDir, e.Attempt))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if p.Intent != nil && p.State != "published" {
				return out, http.StatusServiceUnavailable, "result_pending"
			}
			return out, http.StatusConflict, "result_unknown"
		}
		if errors.Is(err, result.ErrConflict) {
			return out, http.StatusConflict, "result_corrupt"
		}
		return out, http.StatusServiceUnavailable, "result_pending"
	}
	policy := e.ResultPolicy
	if p.Intent != nil {
		if !bytes.Equal(doc, p.Intent.Document) {
			return out, http.StatusConflict, "result_corrupt"
		}
		policy = p.Intent.Policy
	} else {
		// Legacy complete proofs can be read, never reconstructed. The installed
		// trusted public identity must match their signed host claim.
		if m.cfg.Signer == nil {
			return out, http.StatusConflict, "result_unknown"
		}
		policy = m.resultPolicy()
	}
	var identity struct {
		Schema, Attempt, Host string
		State                 State
	}
	if json.Unmarshal(doc, &identity) != nil || identity.Schema != result.Schema || identity.Attempt != e.Attempt || identity.State != e.State || identity.Host != policy.KeyID {
		return out, http.StatusConflict, "result_corrupt"
	}
	if policy.Mode == "signed" {
		if len(sig) == 0 {
			if p.Intent != nil && p.State != "published" {
				return out, http.StatusServiceUnavailable, "result_pending"
			}
			return out, http.StatusConflict, "result_unknown"
		}
		if !result.Verify(policy.PublicKey, doc, sig) {
			return out, http.StatusConflict, "result_corrupt"
		}
		out.KeyID = policy.KeyID
		out.Signature = encodeSignature(sig)
	} else if p.Intent == nil || policy.Mode != "unsigned-development" || len(sig) != 0 {
		return out, http.StatusConflict, "result_corrupt"
	}
	if p.Intent != nil && !e.completionSaved {
		return ResultReply{}, http.StatusServiceUnavailable, "result_pending"
	}
	out.Result = doc
	return out, http.StatusOK, ""
}

// A complete publication whose table acknowledgment was lost stays protected
// until the table transition is durably saved. Legacy evidence is disposable
// only when independently verifiable; unknown or incomplete evidence is held.
func (m *Manager) resultDisposable(e Entry) bool {
	if !e.Terminal() {
		return false
	}
	if e.ClosureRequired {
		if _, status, _ := m.closureRead(e); status != http.StatusOK {
			return false
		}
	}
	if e.Publication.Intent != nil && (!e.completionSaved || e.Publication.State != "published") {
		return false
	}
	_, status, _ := m.publicationRead(e)
	return status == http.StatusOK
}

// recoverResults runs on startup and on every poll, including when no execution
// is live. The manager lock serializes finalizers and retention. At most sixteen
// due entries are attempted per tick; errors use persisted capped backoff.
func (m *Manager) recoverResults(now time.Time) {
	m.mu.Lock()
	defer func() {
		m.mu.Unlock()
		// VM custody is independent of publication, including corrupt/legacy
		// records. Removal runs without the admission/status lock.
		m.cleanupTerminalVMs()
		m.recoverClosures(now)
	}()
	count := 0
	entries := m.t.list()
	start := m.resultCursor
	for offset := 0; offset < len(entries); offset++ {
		index := (start + offset) % len(entries)
		e := m.t.entries[entries[index].Attempt]
		p := &e.Publication
		if !e.Terminal() || p.Intent == nil || p.State == "corrupt" || p.State == "unknown" {
			continue
		}
		// Stable acknowledged publications are verified by each actual reader.
		// They must not consume retry capacity on every subsequent tick.
		if p.State == "published" && e.completionSaved {
			continue
		}
		if count >= 16 {
			break
		}
		m.resultCursor = (index + 1) % len(entries)
		if p.State == "published" {
			count++
			if !validIntent(*e) {
				p.State, p.Error = "corrupt", "completion_intent_invalid"
				_ = m.t.save()
				continue
			}
			if !e.completionSaved {
				if m.t.save() != nil {
					continue
				}
				e.completionSaved = true
			}
			_, status, _ := m.publicationRead(*e)
			if status == http.StatusConflict {
				p.State, p.Error = "corrupt", "published_evidence_changed"
				_ = m.t.save()
				continue
			}
			if status != http.StatusOK {
				continue
			}

			continue
		}
		if now.Before(p.NextRetry) || count >= 16 {
			continue
		}
		count++
		if !validIntent(*e) {
			p.State, p.Error = "corrupt", "completion_intent_invalid"
			_ = m.t.save()
			continue
		}
		// A failed terminal transaction is retried before touching result names.
		if !e.completionSaved {
			if err := m.t.save(); err != nil {
				m.event("result-persist-error", e.Attempt, e.PID, err.Error())
				continue
			}
			e.completionSaved = true
		}
		var sig []byte
		var err error
		_, readStatus, _ := m.publicationRead(*e)
		if readStatus == http.StatusOK {
			// A complete original pair does not need the private signer again. Verify
			// against its frozen public binding and reconcile only the acknowledgment.
			doc, proof, readErr := result.Read(filepath.Join(m.cfg.Venue.Root(), attemptsDir, e.Attempt))
			if readErr != nil {
				err = readErr
			} else {
				err = result.Publish(filepath.Join(m.cfg.Venue.Root(), attemptsDir, e.Attempt), doc, proof)
			}
			p.Error = ""
		} else if readStatus == http.StatusConflict {
			err = result.ErrConflict
			p.Error = ""
		} else if p.Intent.Policy.Mode == "signed" {
			s := m.cfg.Signer
			if s == nil || s.ID != p.Intent.Policy.KeyID || !bytes.Equal(s.Public(), p.Intent.Policy.PublicKey) {
				p.State, p.Error = "held", "key_unavailable"
			} else {
				sig = s.Sign(p.Intent.Document)
				err = result.Publish(filepath.Join(m.cfg.Venue.Root(), attemptsDir, e.Attempt), p.Intent.Document, sig)
				p.Error = ""
			}
		} else {
			err = result.Publish(filepath.Join(m.cfg.Venue.Root(), attemptsDir, e.Attempt), p.Intent.Document, nil)
			p.Error = ""
		}
		if p.Error == "key_unavailable" { /* original identity remains pinned */
		} else if errors.Is(err, result.ErrConflict) {
			p.State, p.Error = "corrupt", "result_conflict"
		} else if err != nil {
			p.State, p.Error = "pending", "storage_unavailable"
		} else {
			p.State, p.Error = "published", ""
		}
		if p.State == "published" {
			m.checkPublicationReadback(e)
		}
		p.Attempts++
		delay := time.Second << min(p.Attempts-1, 6)
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
		p.NextRetry = now.Add(delay)
		if p.State == "published" {
			p.NextRetry = time.Time{}
		}
		// If acknowledgment persistence fails, retain custody and retry it later.
		if err := m.t.save(); err != nil {
			e.completionSaved = false
			m.event("result-persist-error", e.Attempt, e.PID, err.Error())
			continue
		}
		if p.State == "published" {
			m.event("result-written", e.Attempt, e.PID, p.Intent.Policy.Mode)
		}
	}
}

// checkPublicationReadback classifies the actual existing authorized reader,
// after publication and before any custody release.
func (m *Manager) checkPublicationReadback(e *Entry) {
	_, status, _ := m.publicationRead(*e)
	if status == http.StatusConflict {
		e.Publication.State, e.Publication.Error = "corrupt", "publication_readback_failed"
	} else if status != http.StatusOK {
		// A transient reader/storage refusal is not evidence of conflicting
		// bytes. Preserve the original intent and custody for later retry.
		e.Publication.State, e.Publication.Error = "pending", "storage_unavailable"
	}
}
