//go:build darwin

package serviceupgrade

// sow: pomar-SOW-87. Real private directory and synced intent, no service/root act.
import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpeningDirectoryRemainsPrivateUntilSyncedIntentInBothModes(t *testing.T) {
	for _, prefix := range []string{"opening", "rollback-opening"} {
		t.Run(prefix, func(t *testing.T) {
			root := t.TempDir()
			run := filepath.Join(root, "run")
			if err := os.Mkdir(run, 0700); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			// Reopening the inode models the persistent fence after a manager
			// restart; it must not depend on that process's in-memory drain.
			if err := controlDirectoryMode(run, uid, 0700); err != nil {
				t.Fatal(err)
			}
			st, err := os.Stat(run)
			if err != nil || st.Mode().Perm() != 0700 {
				t.Fatal("caller ancestry exposed", err)
			}
			journal := filepath.Join(root, "journal.json")
			phase := prefix
			save := func(step string) error {
				phase = prefix + "-" + step
				b, _ := json.Marshal(Journal{Phase: phase})
				return durableWriteOwned(journal, b, 0600, uid)
			}
			drained := false
			expose := func() error {
				b, err := os.ReadFile(journal)
				if err != nil {
					return err
				}
				var j Journal
				if err := json.Unmarshal(b, &j); err != nil {
					return err
				}
				if j.Phase != prefix+"-exposing" || !drained {
					t.Fatal("permission effect before committed intent")
				}
				if err := controlDirectoryMode(run, uid, 0750); err != nil {
					return err
				}
				return errors.New("crash immediately after chmod")
			}
			if err := reopenAdmission(context.Background(), save, func(on bool) error { drained = on; return nil }, expose, func() error { t.Fatal("unreached caller"); return nil }); err == nil {
				t.Fatal("crash not reached")
			}
			if !openingPhase(phase) {
				t.Fatal("lost explicit post-reversible boundary", phase)
			}
			// The ordinary table guard still owns rollback eligibility after
			// this crash. A new admitted original must survive a refusal.
			_, target, archive, pin, before, _ := migratedManagerTable(t)
			current := []byte(`{"schema":"pomar.manager-table/v2","entries":[{"attempt":"original","state":"exited"},{"attempt":"after-opening","state":"running"}]}`)
			if err := os.WriteFile(target, current, 0600); err != nil {
				t.Fatal(err)
			}
			if err := restoreManagerTable(target, archive, pin, uid, uid, before); err == nil {
				t.Fatal("rollback erased post-opening work")
			}
			got, err := os.ReadFile(target)
			if err != nil || string(got) != string(current) {
				t.Fatal("refusal lost evidence", err)
			}
		})
	}
}
