package manager

// sow: pomar-SOW-87. The legacy decoder must fail before dropping new evidence.
import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVersionedTableRefusesLegacyDecoderAndPreservesIntents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "table.json")
	legacy := []byte(`[{"attempt":"original","state":"exited","publication":{"state":"held","intent":{"document":"e30=","sha256":"fixture","policy":{"mode":"signed","key_id":"original-key"}}},"closure_required":true,"closure":{"state":"pending","intent":{"document":"e30=","sha256":"closure-fixture","policy":{"mode":"signed","key_id":"original-key"}}}}]`)
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	table, err := loadTable(path)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC()
	table.entries["original"].ClosureObservationDeadline = deadline
	if err := table.save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var oldDecoder []*Entry
	if err := json.Unmarshal(raw, &oldDecoder); err == nil {
		t.Fatal("legacy array decoder can load v2 and drop new evidence on save")
	}
	loaded, err := loadTable(path)
	if err != nil {
		t.Fatal(err)
	}
	got := loaded.entries["original"]
	if got == nil || got.Publication.Intent == nil || got.Closure.Intent == nil || !got.ClosureRequired || !got.ClosureObservationDeadline.Equal(deadline) || !bytes.Equal(got.Publication.Intent.Document, []byte("{}")) || got.Closure.Intent.Policy.KeyID != "original-key" {
		t.Fatal("migration or reload lost original obligations", got)
	}
}

func TestVersionedTableRefusesUnsupportedOrIncompleteEnvelope(t *testing.T) {
	for _, raw := range []string{
		`{"schema":"pomar.manager-table/v3","entries":[]}`,
		`{"schema":"pomar.manager-table/v2"}`,
		`{"schema":"pomar.manager-table/v2","entries":null}`,
		`{"schema":"pomar.manager-table/v2","entries":[],"unknown_obligation":true}`,
	} {
		path := filepath.Join(t.TempDir(), "table.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTable(path); err == nil {
			t.Fatal("unsupported table accepted", raw)
		}
	}
}
