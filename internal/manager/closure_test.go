package manager

// sow: pomar-SOW-87. Persisted-boundary fixtures, not real VM or power-loss proof.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/result"
	"github.com/zeroemployeeorg/pomar/internal/venue"
)

func closureFixture(t *testing.T, m *Manager, id string) (Entry, string) {
	t.Helper()
	e, dir := prepareCompletion(t, m, id)
	e.PID = 43210
	e.Start = "fixture-original-helper-birth"
	e.Peaks.VMPID = 43211
	e.Peaks.VMStart = "fixture-linked-vm-birth"
	e.Pins = &Pins{HostBin: "fixture-original-helper-sha256"}
	e.ClosureRequired = true
	e.Publication = Publication{}
	m.freezeResult(&e)
	m.t.entries[id] = &e
	put(t, m.cfg.Venue, venue.KindVM, venue.ClassAttempt, id, "store/containers/"+id, 1)
	if err := m.cfg.Venue.Teardown(venue.KindVM, id); err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{"phase": "exited", "attempt": id, "cleanup_schema": result.CleanupSchema, "cleanup_helper_pid": "43210", "cleanup_stop_acknowledged": "true", "cleanup_delete_acknowledged": "true"}
	b, _ := json.Marshal(fields)
	if err := os.WriteFile(filepath.Join(dir, "status.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.t.save(); err != nil {
		t.Fatal(err)
	}
	e.completionSaved = true
	return e, dir
}
func closureRequest(m *Manager, id string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/v1/attempts/"+id+"/closure", nil)
	r = r.WithContext(context.WithValue(r.Context(), callerKey{}, caller{known: true, uid: uint32(m.cfg.UID)}))
	w := httptest.NewRecorder()
	m.mux(true).ServeHTTP(w, r)
	return w
}
func TestClosurePublicReaderBindsOriginalResultAndPositiveCleanup(t *testing.T) {
	m, _, _ := openSigning(t, true)
	e, _ := closureFixture(t, m, "closure-original")
	m.recoverResults(time.Now())
	w := closureRequest(m, e.Attempt)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var reply struct {
		Closure   json.RawMessage `json:"closure"`
		Signature string          `json:"signature"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if !result.Verify(m.cfg.Signer.Public(), reply.Closure, decodeClosureSignature(reply.Signature)) {
		t.Fatal("closure signature invalid")
	}
	var d ClosureDocument
	if err := json.Unmarshal(reply.Closure, &d); err != nil {
		t.Fatal(err)
	}
	if d.ResultSHA256 != e.Publication.Intent.SHA256 || d.HelperStart != e.Start || !d.StopAcknowledged || !d.OwnedObjectRemoved {
		t.Fatal("wrong binding", d)
	}
	if !m.resultDisposable(*m.t.entries[e.Attempt]) {
		t.Fatal("fully acknowledged result and closure not disposable")
	}
	if bytes.Contains(w.Body.Bytes(), []byte(`"result":`)) {
		t.Fatal("closure endpoint changed result wrapper")
	}
}
func TestClosureInterruptedPublicationRecoversOriginalWithPinnedKey(t *testing.T) {
	m, _, _ := openSigning(t, true)
	e, dir := closureFixture(t, m, "closure-interrupted")
	signer := m.cfg.Signer
	m.cfg.Signer = nil
	m.recoverClosures(time.Now())
	p := m.t.entries[e.Attempt].Closure
	if p.Intent == nil || p.State != "held" || p.Error != "key_unavailable" {
		t.Fatal("missing key did not hold original", p)
	}
	original := bytes.Clone(p.Intent.Document)
	if err := os.WriteFile(filepath.Join(dir, "closure.json"), original, 0400); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadTable(m.t.path)
	if err != nil {
		t.Fatal(err)
	}
	m.t = loaded
	m.cfg.Signer = signer
	m.recoverClosures(time.Now().Add(2 * time.Second))
	doc, sig, err := result.ReadClosure(dir)
	if err != nil || !bytes.Equal(doc, original) || !result.Verify(signer.Public(), doc, sig) {
		t.Fatal("original closure not recovered", err)
	}
	if w := closureRequest(m, e.Attempt); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(m.t.entries) != 1 || m.t.entries[e.Attempt].State != e.State || m.t.entries[e.Attempt].PID != e.PID {
		t.Fatal("original execution changed")
	}
}
func TestClosureUnknownOrFailedAcknowledgmentNeverBecomesSuccess(t *testing.T) {
	for _, fault := range []string{"missing-status", "failed-stop", "unlinked-vm", "missing-owned-record", "status-symlink"} {
		t.Run(fault, func(t *testing.T) {
			m, _, _ := openSigning(t, true)
			e, dir := closureFixture(t, m, "closure-held")
			switch fault {
			case "missing-status":
				os.Remove(filepath.Join(dir, "status.json"))
			case "failed-stop":
				os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"phase":"exited","attempt":"closure-held","cleanup_schema":"pomar.vm-cleanup/v1","cleanup_helper_pid":"43210","cleanup_stop_acknowledged":"false","cleanup_delete_acknowledged":"true"}`), 0600)
			case "unlinked-vm":
				m.t.entries[e.Attempt].Peaks.VMPID = 0
			case "missing-owned-record":
				put(t, m.cfg.Venue, venue.KindVM, venue.ClassAttempt, e.Attempt, "different/"+e.Attempt, 1)
				if err := m.cfg.Venue.Teardown(venue.KindVM, e.Attempt); err != nil {
					t.Fatal(err)
				}
			case "status-symlink":
				b, _ := os.ReadFile(filepath.Join(dir, "status.json"))
				outside := filepath.Join(t.TempDir(), "foreign")
				os.WriteFile(outside, b, 0600)
				os.Remove(filepath.Join(dir, "status.json"))
				os.Symlink(outside, filepath.Join(dir, "status.json"))
			}
			m.recoverClosures(time.Now())
			if w := closureRequest(m, e.Attempt); w.Code == 200 {
				t.Fatal("uncertain cleanup exposed success", w.Body.String())
			}
			if m.resultDisposable(*m.t.entries[e.Attempt]) {
				t.Fatal("held evidence became removable")
			}
		})
	}
}
func TestClosureConflictPreservesOriginal(t *testing.T) {
	m, _, _ := openSigning(t, true)
	e, dir := closureFixture(t, m, "closure-conflict")
	signer := m.cfg.Signer
	m.cfg.Signer = nil
	m.recoverClosures(time.Now())
	intent := bytes.Clone(m.t.entries[e.Attempt].Closure.Intent.Document)
	// Foreign bytes are evidence of conflict, not an opportunity to rewrite.
	if err := os.WriteFile(filepath.Join(dir, "closure.json"), []byte(`{"foreign":true}`), 0400); err != nil {
		t.Fatal(err)
	}
	m.cfg.Signer = signer
	m.recoverClosures(time.Now().Add(2 * time.Second))
	if w := closureRequest(m, e.Attempt); w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !bytes.Equal(intent, m.t.entries[e.Attempt].Closure.Intent.Document) || m.resultDisposable(*m.t.entries[e.Attempt]) {
		t.Fatal("conflict lost original intent/retention")
	}
}

func TestClosureKeyRotationHoldsOriginalUntilItsSignerReturns(t *testing.T) {
	m, _, _ := openSigning(t, true)
	other, _, _ := openSigning(t, true)
	e, dir := closureFixture(t, m, "closure-rotation")
	signer := m.cfg.Signer
	m.cfg.Signer = nil
	m.recoverClosures(time.Now())
	original := bytes.Clone(m.t.entries[e.Attempt].Closure.Intent.Document)
	m.cfg.Signer = other.cfg.Signer
	m.recoverClosures(time.Now().Add(2 * time.Second))
	if got := m.t.entries[e.Attempt].Closure; got.State != "held" || got.Error != "key_unavailable" {
		t.Fatal("rotated key signed original", got)
	}
	if _, _, err := result.ReadClosure(dir); !os.IsNotExist(err) {
		t.Fatal("rotation published proof", err)
	}
	m.cfg.Signer = signer
	m.recoverClosures(time.Now().Add(4 * time.Second))
	doc, sig, err := result.ReadClosure(dir)
	if err != nil || !bytes.Equal(doc, original) || !result.Verify(signer.Public(), doc, sig) {
		t.Fatal("original key did not recover original", err)
	}
}

func TestHeldClosuresCannotStarveTheNextOriginal(t *testing.T) {
	m, _, _ := openSigning(t, true)
	for n := 0; n < 17; n++ {
		id := fmt.Sprintf("closure-old-%02d", n)
		e, dir := closureFixture(t, m, id)
		os.Remove(filepath.Join(dir, "status.json"))
		m.t.entries[e.Attempt].Created = time.Now().Add(-time.Hour + time.Duration(n)*time.Second)
		m.t.entries[e.Attempt].Publication = Publication{}
		m.freezeResult(m.t.entries[e.Attempt])
	}
	e, _ := closureFixture(t, m, "closure-new")
	now := time.Now()
	m.recoverClosures(now)
	m.recoverClosures(now.Add(2 * time.Second))
	if got := m.t.entries[e.Attempt].Closure.State; got != "published" {
		t.Fatal("held predecessors starved current closure", got)
	}
}
