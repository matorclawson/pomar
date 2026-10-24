package serviceupgrade

// sow: pomar-SOW-87. Real target Open migrates a private fixture; no VM or signer.
import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	hostcapacity "github.com/zeroemployeeorg/pomar/internal/capacity"
	"github.com/zeroemployeeorg/pomar/internal/manager"
	"github.com/zeroemployeeorg/pomar/internal/proc"
	"github.com/zeroemployeeorg/pomar/internal/venue"
)

type noTableProcesses struct{}

func (noTableProcesses) List() ([]proc.Process, error) { return nil, nil }

func migratedManagerTable(t *testing.T) (string, string, string, FilePin, string, []byte) {
	t.Helper()
	return migratedManagerTableAt(t, t.TempDir())
}

func migratedManagerTableAt(t *testing.T, root string) (string, string, string, FilePin, string, []byte) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(root, "manager"), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "manager", "table.json")
	// Whitespace deliberately differs from the serializer: restore exact bytes.
	now := time.Now().UTC().Truncate(time.Second)
	exit := 0
	rows, err := json.MarshalIndent([]manager.Entry{{Attempt: "original", Command: []string{"fixture-only"}, State: manager.StateExited, Created: now, Ended: now, ExitCode: &exit}}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	original := append(append([]byte(" \n"), rows...), '\n')
	if err := os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	pin := FilePin{digest(original), int64(len(original))}
	archive := filepath.Join(t.TempDir(), "manager-table.json")
	if err := archiveManagerTable(target, archive, pin, uid, uid); err != nil {
		t.Fatal(err)
	}
	before, _ := managerTableHistory(original)
	v, err := venue.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manager.Open(manager.Config{Venue: v, Procs: noTableProcesses{}, UID: os.Getuid(), Host: hostcapacity.Host{CPUSlots: 2, MemoryBytes: 8 << 30}, Poll: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	return root, target, archive, pin, before, original
}

func TestManagerTableRollbackAfterActualTargetStartup(t *testing.T) {
	_, target, archive, pin, before, original := migratedManagerTable(t)
	uid := uint32(os.Getuid())
	migrated, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var oldDecoder []json.RawMessage
	if json.Unmarshal(migrated, &oldDecoder) == nil {
		t.Fatal("omitting table restoration would not detect legacy decoder incompatibility")
	}
	if err := restoreManagerTable(target, archive, pin, uid, uid, before); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatal("did not restore original bytes")
	}
	if err := json.Unmarshal(restored, &oldDecoder); err != nil {
		t.Fatal("legacy array decoder cannot reopen", err)
	}
	st, _ := os.Stat(target)
	if st.Mode().Perm() != 0600 {
		t.Fatal("table must remain private")
	}
}

func TestManagerTableRollbackRetainsNewObligations(t *testing.T) {
	original := []byte(`[{"attempt":"original","state":"exited","unrecognized_evidence":9007199254740993}]`)
	for name, current := range map[string][]byte{
		"new original":             []byte(`{"schema":"pomar.manager-table/v2","entries":[{"attempt":"new","state":"exited"}]}`),
		"new publication":          []byte(`{"schema":"pomar.manager-table/v2","entries":[{"attempt":"original","state":"exited","unrecognized_evidence":9007199254740993,"publication":{"state":"pending"}}]}`),
		"unknown evidence changed": []byte(`[{"attempt":"original","state":"exited","unrecognized_evidence":9007199254740992}]`),
		"live":                     []byte(`[{"attempt":"original","state":"running"}]`),
		"unsupported schema":       []byte(`{"schema":"pomar.manager-table/v3","entries":[]}`),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "table.json")
			archive := filepath.Join(root, "archive.json")
			uid := uint32(os.Getuid())
			pin := FilePin{digest(original), int64(len(original))}
			before, _ := managerTableHistory(original)
			if err := os.WriteFile(target, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := archiveManagerTable(target, archive, pin, uid, uid); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, current, 0600); err != nil {
				t.Fatal(err)
			}
			if err := restoreManagerTable(target, archive, pin, uid, uid, before); err == nil {
				t.Fatal("discarded new/unknown obligation")
			}
			got, _ := os.ReadFile(target)
			if !bytes.Equal(got, current) {
				t.Fatal("refusal changed current table")
			}
		})
	}
}

func TestManagerTableArchiveIsRequiredAndPinned(t *testing.T) {
	for _, kind := range []string{"missing", "changed", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			d := t.TempDir()
			target := filepath.Join(d, "table.json")
			archive := filepath.Join(d, "archive.json")
			uid := uint32(os.Getuid())
			raw := []byte("[]\n")
			pin := FilePin{digest(raw), int64(len(raw))}
			h, _ := managerTableHistory(raw)
			if err := os.WriteFile(target, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "changed" {
				if err := os.WriteFile(archive, []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink" {
				if err := os.Symlink(target, archive); err != nil {
					t.Fatal(err)
				}
			}
			if err := restoreManagerTable(target, archive, pin, uid, uid, h); err == nil {
				t.Fatal("invalid archive accepted")
			}
			got, _ := os.ReadFile(target)
			if !bytes.Equal(got, raw) {
				t.Fatal("invalid archive changed table")
			}
		})
	}
}

// Exercise the real target startup before adding evidence: rollback must not
// turn an otherwise valid schema migration into permission to erase later work.
func TestManagerTableRollbackRefusesEvidenceAddedAfterTargetStartup(t *testing.T) {
	for _, change := range []string{"additional attempt", "completion intent", "published completion", "closure intent", "closure published"} {
		t.Run(change, func(t *testing.T) {
			_, target, archive, pin, before, _ := migratedManagerTable(t)
			migrated, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(migrated, &envelope); err != nil {
				t.Fatal(err)
			}
			var rows []map[string]json.RawMessage
			if err := json.Unmarshal(envelope["entries"], &rows); err != nil || len(rows) != 1 {
				t.Fatal("expected migrated original", err)
			}
			switch change {
			case "additional attempt":
				// Keep the original too; this is a new obligation, not merely a
				// replacement or deletion of the archived row.
				rows = append(rows, map[string]json.RawMessage{
					"attempt": json.RawMessage(`"later-original"`),
					"state":   json.RawMessage(`"exited"`),
				})
			case "completion intent":
				rows[0]["publication"] = json.RawMessage(`{"state":"pending","intent":{"document":"e30=","sha256":"new-frozen-completion","policy":{"mode":"unsigned-development","purpose":"fixture"}}}`)
			case "published completion":
				rows[0]["publication"] = json.RawMessage(`{"state":"published","intent":{"document":"e30=","sha256":"new-frozen-completion","policy":{"mode":"unsigned-development","purpose":"fixture"}}}`)
			case "closure intent":
				rows[0]["closure"] = json.RawMessage(`{"state":"pending","intent":{"document":"e30=","sha256":"new-frozen-closure","policy":{"mode":"unsigned-development","purpose":"fixture"}}}`)
			case "closure published":
				rows[0]["closure"] = json.RawMessage(`{"state":"published","intent":{"document":"e30=","sha256":"new-frozen-closure","policy":{"mode":"unsigned-development","purpose":"fixture"}}}`)
			}
			envelope["entries"], err = json.Marshal(rows)
			if err != nil {
				t.Fatal(err)
			}
			current, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, current, 0600); err != nil {
				t.Fatal(err)
			}
			archived, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			if err := restoreManagerTable(target, archive, pin, uid, uid, before); err == nil {
				t.Fatal("rollback discarded post-upgrade evidence")
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, current) {
				t.Fatal("refusal changed current evidence", err)
			}
			got, err = os.ReadFile(archive)
			if err != nil || !bytes.Equal(got, archived) {
				t.Fatal("refusal changed original archive", err)
			}
		})
	}
}

func TestManagerTableManifestRequiresFrozenSnapshot(t *testing.T) {
	for _, pin := range []FilePin{{}, {"bad", 2}, {digest([]byte("[]")), maxManagerTable + 1}} {
		m := fixtureManifest()
		m.ManagerTable = pin
		if m.Validate() == nil {
			t.Fatal("missing/invalid table pin accepted")
		}
	}
}
