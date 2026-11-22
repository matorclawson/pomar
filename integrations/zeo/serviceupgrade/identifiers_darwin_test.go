package serviceupgrade

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func fixturePlist(label, argument string) []byte {
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>/usr/local/libexec/pomar/pomar</string><string>%s</string></array>
<key>KeepAlive</key><true/>
</dict></plist>
`, label, argument)
}

func TestMigrationChangesOnlyLabelAndRestoresOriginalPlist(t *testing.T) {
	ctx := context.Background()
	old := fixturePlist(legacyLabel, "serve")
	next := fixturePlist(neutralLabel, "serve")
	if err := comparePlists(ctx, old, next); err != nil {
		t.Fatal(err)
	}
	if err := comparePlists(ctx, old, fixturePlist(neutralLabel, "other")); err == nil {
		t.Fatal("migration accepted changed launch arguments")
	}
	if err := comparePlists(ctx, old, old); err == nil {
		t.Fatal("migration accepted the old label on the target")
	}

	m := fixtureManifest()
	m.Retained["plist"] = FilePin{digest(old), int64(len(old))}
	m.Identifiers = &Identifiers{Mode: "legacy_to_neutral", TargetPlist: &FilePin{digest(next), int64(len(next))}}
	p := launchPlists{dir: t.TempDir(), uid: uint32(os.Getuid()), manifest: m}
	if err := os.WriteFile(p.path(legacyLabel), old, 0640); err != nil {
		t.Fatal(err)
	}
	saved, err := pinnedOwnedFile(p.path(legacyLabel), m.Retained["plist"], p.uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.publish(neutralLabel, next, 0644); err == nil {
		t.Fatal("could publish a second startup plist")
	}
	if err := p.remove(); err != nil {
		t.Fatal(err)
	}
	// Reopen the directory after an interrupted switch.
	if err := p.require(""); err != nil {
		t.Fatal(err)
	}
	if err := p.publish(neutralLabel, next, 0644); err != nil {
		t.Fatal(err)
	}
	if err := p.remove(); err != nil {
		t.Fatal(err)
	}
	if err := p.publish(legacyLabel, saved, 0640); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p.path(legacyLabel))
	if err != nil || !bytes.Equal(got, old) {
		t.Fatalf("rollback did not restore exact bytes: %v", err)
	}
	if st, err := os.Stat(p.path(legacyLabel)); err != nil || st.Mode().Perm() != 0640 {
		t.Fatalf("rollback did not restore the archived permission mode: %v, %v", st, err)
	}
	if err := os.WriteFile(p.path(neutralLabel), next, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.current(); err == nil {
		t.Fatal("two installed plists should hold the operation")
	}
	if _, err := loadedService([]byte("PID Status Label\n101 0 " + legacyLabel + "\n- 0 " + neutralLabel)); err == nil {
		t.Fatal("two loaded services should hold the operation, even with a stopped PID")
	}
}

func TestMigrationChecksSignedBinaryIdentityInBothDirections(t *testing.T) {
	ctx := context.Background()
	m := fixtureManifest()
	m.SigningPolicy = "development_transition"
	m.Identifiers = &Identifiers{Mode: "legacy_to_neutral"}
	n := Native{M: m}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []bool{false, true} {
		id := m.signingID("pomar", target)
		t.Run(id, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pomar")
			if err := os.WriteFile(path, binary, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := command(ctx, nil, "/usr/bin/codesign", "--force", "--sign", "-", "--identifier", id, path); err != nil {
				t.Fatal(err)
			}
			if err := n.signature(ctx, path, "pomar", target); err != nil {
				t.Fatal(err)
			}
			if err := n.signature(ctx, path, "pomar", !target); err == nil {
				t.Fatal("the opposite role accepted a real signed binary")
			}
		})
	}
}
