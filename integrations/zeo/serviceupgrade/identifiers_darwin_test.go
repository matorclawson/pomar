package serviceupgrade

import (
	"bytes"
	"context"
	"errors"
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
	if err := p.publish(neutralLabel, next, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p.path(legacyLabel)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the old startup filename still exists: %v", err)
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

func TestRecoverySeparatesLoadedWithoutProcessFromAbsentOrRunning(t *testing.T) {
	const header = "PID Status Label\n"
	for _, tc := range []struct {
		name, row string
		label     string
		pid       int
		bindErr   error
		writers   string
		allow     bool
		wantErr   bool
	}{
		{name: "absent", writers: "1 0 0 /sbin/launchd", allow: true},
		{name: "pinned stopped", row: "- 0 " + neutralLabel, label: neutralLabel, writers: "1 0 0 /sbin/launchd", allow: true},
		{name: "running", row: "901 0 " + neutralLabel, label: neutralLabel, pid: 901, writers: "901 1 410 /usr/local/libexec/pomar/pomar", allow: true},
		{name: "unbound stopped", row: "- 0 " + neutralLabel, label: neutralLabel, bindErr: errors.New("unknown generation"), allow: true, wantErr: true},
		{name: "unknown owner process", row: "- 0 " + neutralLabel, label: neutralLabel, writers: "905 1 410 /path/unknown", allow: true, wantErr: true},
		{name: "running child", row: "901 0 " + neutralLabel, label: neutralLabel, pid: 901, writers: "902 901 410 /path/unknown", allow: true, wantErr: true},
		{name: "v1 stopped", row: "- 0 " + legacyLabel, label: legacyLabel, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job, err := loadedService([]byte(header + tc.row))
			if err != nil || job.label != tc.label || job.pid != tc.pid {
				t.Fatalf("unexpected launchd state: %+v, %v", job, err)
			}
			err = checkRecoveryJob(job, tc.allow, func(label string) error {
				if label == "" || label != tc.label {
					t.Fatalf("unexpected generation binding: %q", label)
				}
				return tc.bindErr
			}, func(pid int) error {
				return checkWriterInventory([]byte(tc.writers), pid, 410, pid == 0)
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected recovery classification: %v", err)
			}
		})
	}
	for _, badPID := range []string{"0", "1", "?", "overflow-999999999"} {
		if _, err := loadedService([]byte(header + badPID + " 0 " + neutralLabel)); err == nil {
			t.Fatalf("invalid PID %q treated as stopped", badPID)
		}
	}
}

type plistMigrationFixture struct {
	fakeDriver
	plists    launchPlists
	archive   []byte
	target    []byte
	active    string
	restoring bool
	interrupt string
}

func (f *plistMigrationFixture) Archive(context.Context, Observation) (string, error) {
	data, err := pinnedOwnedFile(f.plists.path(legacyLabel), f.plists.manifest.Retained["plist"], f.plists.uid)
	f.archive = data
	return "original-archive", err
}

func (f *plistMigrationFixture) Stop(context.Context, Observation) error {
	f.active = ""
	return nil
}

func (f *plistMigrationFixture) Replace(context.Context) error {
	switch f.interrupt {
	case "before-publication":
		return errors.New("injected interruption between binary replacement and plist publication")
	case "after-atomic-replacement":
		if err := durableWriteOwned(f.plists.path(legacyLabel), f.target, 0644, f.plists.uid); err != nil {
			return err
		}
		return errors.New("injected interruption after plist replacement and before rename")
	}
	return f.plists.publish(neutralLabel, f.target, 0644)
}

func (f *plistMigrationFixture) Restore(context.Context, Journal) error {
	f.restoring = true
	f.active = ""
	return f.plists.publish(legacyLabel, f.archive, 0640)
}

func (f *plistMigrationFixture) Start(context.Context) error {
	if f.active != "" {
		return errors.New("a supervisor is still active")
	}
	label := neutralLabel
	if f.restoring {
		label = legacyLabel
	}
	if err := f.plists.require(label); err != nil {
		return err
	}
	f.active = label
	return nil
}

func (f *plistMigrationFixture) Verify(context.Context, Observation) error {
	return f.plists.require(f.active)
}

func TestMigrationTransactionKeepsStartupPlistAndSupportsRollback(t *testing.T) {
	ctx := context.Background()
	old := fixturePlist(legacyLabel, "serve")
	next := fixturePlist(neutralLabel, "serve")
	for _, interrupt := range []string{"complete", "before-publication", "after-atomic-replacement"} {
		t.Run(interrupt, func(t *testing.T) {
			m := fixtureManifest()
			m.Retained["plist"] = FilePin{digest(old), int64(len(old))}
			m.Identifiers = &Identifiers{Mode: "legacy_to_neutral", TargetPlist: &FilePin{digest(next), int64(len(next))}}
			f := &plistMigrationFixture{
				plists: launchPlists{dir: t.TempDir(), uid: uint32(os.Getuid()), manifest: m},
				active: legacyLabel, target: next, interrupt: interrupt,
			}
			if err := os.WriteFile(f.plists.path(legacyLabel), old, 0640); err != nil {
				t.Fatal(err)
			}
			recover := func(ctx context.Context, failed Journal) (Journal, error) {
				installed, err := f.plists.current()
				want := legacyLabel
				if interrupt == "after-atomic-replacement" {
					want = neutralLabel
				}
				if err != nil || f.active != "" || installed.label != want || installed.path != f.plists.path(legacyLabel) {
					t.Fatalf("interruption did not leave exactly one pinned startup file: %+v, %v", installed, err)
				}
				return Rollback(ctx, f, failed, "frozen")
			}
			j, err := apply(ctx, f, "frozen", recover)
			if interrupt != "complete" {
				if err == nil || j.Phase != "rolled-back" {
					t.Fatalf("expected forward error with verified recovery: %+v, %v", j, err)
				}
			} else {
				if err != nil || j.Phase != "complete" || f.active != neutralLabel {
					t.Fatalf("expected neutral service after successful migration: %+v, %v", j, err)
				}
				if j, err = Rollback(ctx, f, j, "frozen"); err != nil || j.Phase != "rolled-back" {
					t.Fatalf("explicit rollback: %+v, %v", j, err)
				}
			}
			if f.active != legacyLabel || f.plists.require(legacyLabel) != nil {
				t.Fatal("original service and exact plist were not restored")
			}
		})
	}
}

type unreadyReplacementFixture struct {
	plistMigrationFixture
	job      launchJob
	verified bool
}

func (f *unreadyReplacementFixture) Start(ctx context.Context) error {
	if err := f.plistMigrationFixture.Start(ctx); err != nil {
		return err
	}
	if f.active == neutralLabel {
		f.job = launchJob{label: neutralLabel, pid: 917}
		return context.DeadlineExceeded // Owner readiness never returned.
	}
	return nil
}

func (f *unreadyReplacementFixture) Restore(ctx context.Context, j Journal) error {
	if !recoverBeforeReadiness(true, j, f.job) {
		return errors.New("normal recovery would require the unavailable owner API")
	}
	if err := bootoutRecoveryJob(f.job, "original birth", func() (launchJob, string, error) {
		return f.job, "original birth", nil
	}, func(label string) error {
		if label != neutralLabel {
			return errors.New("bootout selected the wrong label")
		}
		f.job = launchJob{}
		return nil
	}, func(pid int) error {
		if pid != 917 || f.job.pid != 0 {
			return errors.New("pinned replacement PID still running")
		}
		return nil
	}); err != nil {
		return err
	}
	return f.plistMigrationFixture.Restore(ctx, j)
}

func (f *unreadyReplacementFixture) Verify(ctx context.Context, before Observation) error {
	if f.active != legacyLabel || f.job.pid != 0 || before.Pin != "baseline" {
		return errors.New("original service was not restored")
	}
	if err := f.plistMigrationFixture.Verify(ctx, before); err != nil {
		return err
	}
	f.verified = true
	return nil
}

func TestMigrationRestoresLegacyWhenReplacementOwnerNeverAnswers(t *testing.T) {
	old := fixturePlist(legacyLabel, "serve")
	next := fixturePlist(neutralLabel, "serve")
	m := fixtureManifest()
	m.Retained["plist"] = FilePin{digest(old), int64(len(old))}
	m.Identifiers = &Identifiers{Mode: "legacy_to_neutral", TargetPlist: &FilePin{digest(next), int64(len(next))}}
	f := &unreadyReplacementFixture{plistMigrationFixture: plistMigrationFixture{
		plists: launchPlists{dir: t.TempDir(), uid: uint32(os.Getuid()), manifest: m},
		active: legacyLabel, target: next,
	}}
	if err := os.WriteFile(f.plists.path(legacyLabel), old, 0640); err != nil {
		t.Fatal(err)
	}
	j, err := apply(context.Background(), f, "frozen", func(ctx context.Context, failed Journal) (Journal, error) {
		if !recoverBeforeReadiness(true, failed, f.job) {
			t.Fatal("a pinned running replacement during startup needs the launchd recovery route")
		}
		return Rollback(ctx, f, failed, "frozen")
	})
	if !errors.Is(err, context.DeadlineExceeded) || j.Phase != "rolled-back" || j.FromStartup || !f.verified {
		t.Fatalf("startup timeout did not preserve the original error and verify rollback: %+v, %v", j, err)
	}
}

func TestStartupRecoveryRefusesLaterPhasesAndChangedProcessIdentity(t *testing.T) {
	job := launchJob{label: neutralLabel, pid: 917}
	for _, j := range []Journal{
		{Phase: "installing"}, {Phase: "verifying"}, {Phase: "complete"}, {Phase: "rolling-back"},
	} {
		if recoverBeforeReadiness(true, j, job) {
			t.Fatalf("bypassed owner API from phase %s", j.Phase)
		}
	}
	j := Journal{Phase: "rolling-back", FromStartup: true}
	if !recoverBeforeReadiness(true, j, job) ||
		recoverBeforeReadiness(false, j, job) ||
		recoverBeforeReadiness(true, j, launchJob{label: legacyLabel, pid: job.pid}) {
		t.Fatal("startup recovery did not bind the migration direction and original rollback phase")
	}
	if err := bootoutRecoveryJob(job, "original birth", func() (launchJob, string, error) {
		return job, "reused PID", nil
	}, func(string) error {
		t.Fatal("issued bootout for changed process identity")
		return nil
	}, func(int) error {
		t.Fatal("waited on an unbound PID")
		return nil
	}); err == nil {
		t.Fatal("accepted changed process identity")
	}
}
