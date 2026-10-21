package manager

// sow: pomar-SOW-87. No VM or permanent service is started by these fixtures.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/cache"
	"github.com/zeroemployeeorg/pomar/internal/result"
	"github.com/zeroemployeeorg/pomar/internal/venue"
)

func terminalVMFixture(t *testing.T, m *Manager, v *venue.Venue, id string) string {
	t.Helper()
	put(t, v, venue.KindVM, venue.ClassAttempt, id, "store/containers/"+id, 16)
	put(t, v, venue.KindVolume, venue.ClassAttempt, "attempt-"+id, "attempts/"+id, 0)
	return filepath.Join(v.Root(), "attempts", id)
}

func TestFinishReleasesVMWithoutLosingUnpublishedEvidence(t *testing.T) {
	for _, mode := range []string{"held", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			m, _, v := openSigning(t, true)
			id := "finish-" + mode
			rec := terminalVMFixture(t, m, v, id)
			e := terminalEntry(id)
			e.State = StateRunning
			e.ResultPolicy = m.resultPolicy()
			if mode == "unknown" {
				e.ResultPolicy = ResultPolicy{}
			} else {
				m.cfg.Signer = nil
			}
			if err := os.WriteFile(filepath.Join(rec, "kept-evidence"), []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			m.t.entries[id] = &e
			zero := 0
			m.finish(id, StateExited, "", &zero)
			if v.IsOpen(venue.KindVM, id) {
				t.Fatal("terminal VM leaked because publication is unresolved")
			}
			if _, err := os.Stat(filepath.Join(v.Root(), "store/containers", id)); !os.IsNotExist(err) {
				t.Fatal("VM data remains", err)
			}
			if got := m.t.entries[id].Publication.State; got != mode {
				t.Fatalf("publication=%s, want%s", got, mode)
			}
			if b, err := os.ReadFile(filepath.Join(rec, "kept-evidence")); err != nil || string(b) != "original" {
				t.Fatal("completion evidence removed", err)
			}
			if err := m.Remove(id); err == nil {
				t.Fatal("unresolved result record became disposable")
			}
		})
	}
}

func TestRecoveryReleasesCorruptUnknownAndHeldVMs(t *testing.T) {
	for _, state := range []string{"corrupt", "unknown", "held"} {
		t.Run(state, func(t *testing.T) {
			m, _, v := openSigning(t, true)
			id := "recover-" + state
			rec := terminalVMFixture(t, m, v, id)
			e, _ := prepareCompletion(t, m, id)
			if state == "held" {
				m.cfg.Signer = nil
			} else {
				m.t.entries[id].Publication.State = state
			}
			if err := m.t.save(); err != nil {
				t.Fatal(err)
			}
			loaded, err := loadTable(m.t.path)
			if err != nil {
				t.Fatal(err)
			}
			m.t = loaded
			m.recoverResults(time.Now())
			if v.IsOpen(venue.KindVM, id) {
				t.Fatal("unpublished terminal VM survived recovery")
			}
			if _, err := os.Stat(rec); err != nil {
				t.Fatal("record removed", err)
			}
			if got := m.t.entries[id].Publication.State; got != state {
				t.Fatalf("publication=%s want%s", got, state)
			}
			if m.t.entries[id].Attempt != e.Attempt || !bytes.Equal(m.t.entries[id].Publication.Intent.Document, e.Publication.Intent.Document) {
				t.Fatal("original intent changed")
			}
			if m.resultDisposable(*m.t.entries[id]) {
				t.Fatal("unresolved evidence became disposable")
			}
		})
	}
}

func TestUnresolvedTerminalRecordDoesNotPinLiveOnlyCache(t *testing.T) {
	m, _, v := openSigning(t, true)
	id := "unresolved-cache"
	put(t, v, venue.KindVolume, venue.ClassCache, "module-cache", "goproxy/test", 64<<10)
	terminalVMFixture(t, m, v, id)
	e := terminalEntry(id)
	e.Publication.State = "unknown"
	m.t.entries[id] = &e
	m.cfg.Budgets = []cache.Budget{{Name: "goproxy", Prefix: "goproxy/", Bytes: 1, Evict: true, Class: venue.ClassCache, KeepWhileLive: true}}
	m.cleanupTerminalVMs()
	rep, err := m.Caches(true)
	if err != nil || len(rep.Errors) != 0 {
		t.Fatal(err, rep.Errors)
	}
	if v.IsOpen(venue.KindVolume, "module-cache") {
		t.Fatal("terminal unresolved record pinned a cache used only by live jobs")
	}
	if !v.IsOpen(venue.KindVolume, "attempt-"+id) {
		t.Fatal("protected completion record evicted")
	}
}

func TestTerminalCleanupDoesNotHoldManagerLockOrAllowOriginalReuse(t *testing.T) {
	m, _, v := openSigning(t, true)
	id := "slow-cleanup"
	terminalVMFixture(t, m, v, id)
	e, _ := prepareCompletion(t, m, id)
	m.recoverResults(time.Now()) // Publish before reinstating the test VM object.
	put(t, v, venue.KindVM, venue.ClassAttempt, id, "store/containers/"+id, 16)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		m.cleanupTerminalVMsWith(func(attempt string) { close(entered); <-release; m.teardownVM(attempt) })
		close(done)
	}()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		<-done
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not enter")
	}
	observed := make(chan bool, 1)
	go func() { m.List(); observed <- true }()
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("slow VM teardown holds the manager lock")
	}
	if err := m.Remove(id); err == nil || !strings.Contains(err.Error(), "cleanup pending") {
		t.Fatal("record removable during VM cleanup", err)
	}
	if m.t.entries[id].Created != e.Created {
		t.Fatal("original replaced while teardown blocked")
	}
	close(release)
	<-done
	if v.IsOpen(venue.KindVM, id) {
		t.Fatal("VM not removed")
	}
}

func TestAcknowledgedResultsDoNotConsumeRecoveryBudgetForever(t *testing.T) {
	m, _, _ := openSigning(t, true)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 17; i++ {
		id := fmt.Sprintf("old-%02d", i)
		_, _ = prepareCompletion(t, m, id)
		m.t.entries[id].Created = base.Add(time.Duration(i) * time.Second)
		m.t.entries[id].Publication = Publication{}
		m.freezeResult(m.t.entries[id])
		m.t.entries[id].completionSaved = false
	}
	m.recoverResults(time.Now())
	m.recoverResults(time.Now())
	for _, e := range m.t.entries {
		if e.Publication.State != "published" || !e.completionSaved {
			t.Fatal("fixture not published", e.Attempt)
		}
	}
	e, _ := prepareCompletion(t, m, "next-pending")
	m.t.entries[e.Attempt].Created = time.Now()
	m.t.entries[e.Attempt].Publication = Publication{}
	m.freezeResult(m.t.entries[e.Attempt])
	m.t.entries[e.Attempt].completionSaved = false
	m.resultCursor = 0
	m.recoverResults(time.Now())
	if m.t.entries[e.Attempt].Publication.State != "published" {
		t.Fatal("already acknowledged results starved new publication")
	}
}

func TestValidLegacySignedResultIsReadableWithoutReconstruction(t *testing.T) {
	m, _, v := openSigning(t, true)
	e := terminalEntry("legacy-positive")
	rec := filepath.Join(v.Root(), attemptsDir, e.Attempt)
	if err := os.MkdirAll(rec, 0700); err != nil {
		t.Fatal(err)
	}
	doc, err := result.Canonical(m.resultDoc(e))
	if err != nil {
		t.Fatal(err)
	}
	sig := m.cfg.Signer.Sign(doc)
	if err := result.Write(rec, doc, sig); err != nil {
		t.Fatal(err)
	}
	m.t.entries[e.Attempt] = &e
	if err := m.t.save(); err != nil {
		t.Fatal(err)
	}
	w := publicationRequest(m, e.Attempt)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var reply ResultReply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply.Result, doc) || !result.Verify(m.cfg.Signer.Public(), reply.Result, sig) {
		t.Fatal("valid legacy proof not preserved")
	}
	if e.Publication.Intent != nil {
		t.Fatal("legacy evidence reconstructed")
	}
}

func TestCompletionTableDirectorySyncOnQualificationFilesystem(t *testing.T) {
	m, _, _ := openSigning(t, true)
	if err := m.t.save(); err != nil {
		t.Fatal("qualification filesystem cannot acknowledge durable manager table", err)
	}
	if _, err := loadTable(m.t.path); err != nil {
		t.Fatal(err)
	}
	t.Log("table file and parent directory sync acknowledged on this test filesystem; not a production-volume or power-loss claim")
}
