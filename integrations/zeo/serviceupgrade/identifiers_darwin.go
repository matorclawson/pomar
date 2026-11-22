package serviceupgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const targetPlistName = "manager-target.plist"
const originalPlistName = "manager-original.plist"

type launchPlists struct {
	dir      string
	uid      uint32
	manifest Manifest
}

func (p launchPlists) path(label string) string {
	return filepath.Join(p.dir, label+".plist")
}

type installedPlist struct {
	label string
	path  string
}

// current binds a single installed file to its pinned contents. Migration
// allows either filename while an atomic label publication is in progress.
func (p launchPlists) current() (installedPlist, error) {
	if err := directory(p.dir, p.uid, 0); err != nil {
		return installedPlist{}, err
	}
	var current installedPlist
	baseline := p.manifest.serviceLabel(false)
	for _, filename := range []string{legacyLabel, neutralLabel} {
		path := p.path(filename)
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return installedPlist{}, err
		}
		if current.path != "" {
			return installedPlist{}, fmt.Errorf("both service plists are installed")
		}
		if !p.manifest.migrating() {
			if filename != baseline {
				return installedPlist{}, fmt.Errorf("unexpected service plist")
			}
			if _, err := pinnedOwnedFile(path, p.manifest.Retained["plist"], p.uid); err != nil {
				return installedPlist{}, err
			}
			current = installedPlist{label: baseline, path: path}
			continue
		}
		data, err := readFile(path, 64<<10, p.uid)
		if err != nil {
			return installedPlist{}, err
		}
		pin := FilePin{SHA256: digest(data), Bytes: int64(len(data))}
		switch pin {
		case p.manifest.Retained["plist"]:
			current = installedPlist{label: legacyLabel, path: path}
		case *p.manifest.Identifiers.TargetPlist:
			current = installedPlist{label: neutralLabel, path: path}
		default:
			return installedPlist{}, fmt.Errorf("installed service plist binding differs")
		}
	}
	return current, nil
}

func (p launchPlists) require(label string) error {
	current, err := p.current()
	if err != nil {
		return err
	}
	if current.label != label {
		return fmt.Errorf("installed service plist differs from %s", label)
	}
	return nil
}

// The caller proves both labels absent from launchd and holds the upgrade
// lock. Swap the contents at the existing filename, then rename the single
// file. A crash between those effects leaves one complete startup plist.
func (p launchPlists) publish(label string, data []byte, mode os.FileMode) error {
	if !p.manifest.migrating() || (label != legacyLabel && label != neutralLabel) {
		return fmt.Errorf("unsupported launch plist publication")
	}
	current, err := p.current()
	if err != nil {
		return err
	}
	pin := p.manifest.Retained["plist"]
	if label == neutralLabel {
		pin = *p.manifest.Identifiers.TargetPlist
	}
	if digest(data) != pin.SHA256 || int64(len(data)) != pin.Bytes {
		return fmt.Errorf("replacement service plist bytes differ")
	}
	target := p.path(label)
	slot := current.path
	if slot == "" {
		// Older interrupted migrations can leave neither file installed.
		slot = target
	}
	if err := durableWriteOwned(slot, data, mode, p.uid); err != nil {
		return err
	}
	if slot != target {
		if err := os.Rename(slot, target); err != nil {
			return err
		}
		if err := syncDirectory(p.dir); err != nil {
			return err
		}
	}
	return p.require(label)
}

func (n *Native) launchPlists() launchPlists {
	return launchPlists{dir: launchDaemons, manifest: n.M}
}

func (n *Native) expectedLabel() string {
	return n.M.serviceLabel(!n.rollback)
}

func (n *Native) originalPlist(path string) ([]byte, os.FileMode, error) {
	b, err := pinnedFile(path, n.M.Retained["plist"])
	if err != nil {
		return nil, 0, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode() != info.Mode().Perm() {
		return nil, 0, fmt.Errorf("legacy launch plist must have root:wheel custody and ordinary permissions")
	}
	return b, info.Mode().Perm(), nil
}

func (n *Native) checkTransitionPlists(ctx context.Context) error {
	p := n.launchPlists()
	if !n.rollback || !n.M.migrating() {
		if err := p.require(n.M.serviceLabel(false)); err != nil {
			return err
		}
	}
	if !n.M.migrating() {
		return nil
	}
	current, err := p.current()
	if err != nil {
		return err
	}
	oldPath := current.path
	if n.rollback {
		oldPath = filepath.Join(n.ArchivePath, originalPlistName)
	}
	old, _, err := n.originalPlist(oldPath)
	if err != nil {
		return err
	}
	next, err := pinnedFile(filepath.Join(n.Bundle, targetPlistName), *n.M.Identifiers.TargetPlist)
	if err != nil {
		return err
	}
	return comparePlists(ctx, old, next)
}

func plistWithoutLabel(ctx context.Context, data []byte, label string) ([]byte, error) {
	out, err := command(ctx, data, "/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
	if err != nil {
		return nil, err
	}
	var props map[string]any
	decoder := json.NewDecoder(bytes.NewReader(out))
	decoder.UseNumber()
	if err := decoder.Decode(&props); err != nil || props["Label"] != label {
		return nil, fmt.Errorf("launch plist Label differs from %s", label)
	}
	delete(props, "Label")
	return json.Marshal(props)
}

func comparePlists(ctx context.Context, old, next []byte) error {
	a, err := plistWithoutLabel(ctx, old, legacyLabel)
	if err != nil {
		return err
	}
	b, err := plistWithoutLabel(ctx, next, neutralLabel)
	if err != nil {
		return err
	}
	if !bytes.Equal(a, b) {
		return fmt.Errorf("migration can change only the launch plist Label")
	}
	return nil
}

type launchJob struct {
	label string
	pid   int // Zero identifies a registered job without a process.
}

func (n *Native) launchJob(ctx context.Context) (launchJob, error) {
	raw, err := command(ctx, nil, "/bin/launchctl", "list")
	if err != nil {
		return launchJob{}, err
	}
	return loadedService(raw)
}

func (n *Native) currentService(ctx context.Context) (string, error) {
	job, err := n.launchJob(ctx)
	if err != nil {
		return "", err
	}
	if job.label == "" {
		return "", fmt.Errorf("service is not loaded")
	}
	if err := n.launchPlists().require(job.label); err != nil {
		return "", err
	}
	return job.label, nil
}

func loadedService(raw []byte) (launchJob, error) {
	rows := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if strings.Join(strings.Fields(rows[0]), " ") != "PID Status Label" {
		return launchJob{}, fmt.Errorf("launchd inventory incomplete")
	}
	var job launchJob
	for _, row := range rows[1:] {
		f := strings.Fields(row)
		if len(f) != 3 {
			return launchJob{}, fmt.Errorf("launchd inventory malformed")
		}
		if f[2] == legacyLabel || f[2] == neutralLabel {
			if job.label != "" {
				return launchJob{}, fmt.Errorf("multiple Pomar services loaded")
			}
			if _, err := strconv.Atoi(f[1]); err != nil {
				return launchJob{}, fmt.Errorf("invalid service status in launchd inventory")
			}
			job.label = f[2]
			if f[0] != "-" {
				pid, err := strconv.Atoi(f[0])
				if err != nil || pid <= 1 {
					return launchJob{}, fmt.Errorf("invalid service PID in launchd inventory")
				}
				job.pid = pid
			}
		}
	}
	return job, nil
}

func (n *Native) recoverMigration(ctx context.Context, failed Journal) (Journal, error) {
	if !n.stopIssued {
		now, err := n.Observe(ctx)
		if err != nil || now != failed.Before {
			return failed, fmt.Errorf("legacy identity changed before bootout; recovery refused")
		}
	}
	original, err := n.LoadRollback(failed.Archive)
	if err != nil {
		return failed, err
	}
	if original.Before != failed.Before {
		return failed, fmt.Errorf("original journal observation differs")
	}
	return Rollback(ctx, n, original, failed.ManifestSHA)
}

// recoveryService distinguishes absence, a registered job without a process,
// and a running job. A failed running-process lookup cannot prove absence.
func (n *Native) recoveryService(ctx context.Context) (launchJob, string, error) {
	job, err := n.launchJob(ctx)
	if err != nil {
		return launchJob{}, "", err
	}
	bind := func(label string) error {
		if err := n.launchPlists().require(label); err != nil {
			return err
		}
		if n.M.migrating() {
			return n.checkInstalledGeneration(label)
		}
		return nil
	}
	if err := checkRecoveryJob(job, n.M.migrating(), bind, func(pid int) error {
		return n.checkWriters(ctx, pid, n.M.migrating() && pid == 0)
	}); err != nil {
		return launchJob{}, "", err
	}
	if job.pid == 0 {
		return job, "", nil
	}
	pid, birth, err := n.processForLabel(ctx, job.label)
	if err != nil || pid != job.pid {
		return launchJob{}, "", fmt.Errorf("running service identity changed during recovery check")
	}
	return job, birth, nil
}

func checkRecoveryJob(job launchJob, allowStopped bool, bind func(string) error, noWriters func(int) error) error {
	if job.label != "" {
		if job.pid == 0 && !allowStopped {
			return fmt.Errorf("registered service has no identified process")
		}
		if err := bind(job.label); err != nil {
			return err
		}
	}
	return noWriters(job.pid)
}

func (n *Native) checkInstalledGeneration(label string) error {
	build, expected := n.M.Baseline, n.beforeRecord
	if label == neutralLabel {
		build = n.M.Target
		var err error
		expected, err = targetRecord(n.beforeRecord, n.M, n.ArchivePath)
		if err != nil {
			return err
		}
	}
	raw, err := readFile(recordPath, 64<<10, 0)
	if err != nil || !bytes.Equal(raw, expected) {
		return fmt.Errorf("registered service record does not match its pinned label")
	}
	for _, name := range binaries {
		if _, err := pinnedFile(filepath.Join(bindir, name), build.Binaries[name]); err != nil {
			return fmt.Errorf("registered service %s does not match its pinned label", name)
		}
	}
	return nil
}

func recoverBeforeReadiness(migrating bool, j Journal, job launchJob) bool {
	// Start runs with the caller directory closed. Verify is the first
	// phase that can open it, so later phases still require owner readback.
	return migrating && job.label == neutralLabel && job.pid > 1 &&
		(j.Phase == "starting" || (j.Phase == "rolling-back" && j.FromStartup))
}

func (n *Native) unloadForRecovery(ctx context.Context, expected launchJob, birth string) error {
	if err := directory(runDir, n.M.OwnerUID, 0700); err != nil {
		return err
	}
	if err := bootoutRecoveryJob(expected, birth, func() (launchJob, string, error) {
		return n.recoveryService(ctx)
	}, func(label string) error {
		_, err := command(ctx, nil, "/bin/launchctl", "bootout", "system/"+label)
		return err
	}, func(pid int) error {
		return n.waitAbsent(ctx, pid)
	}); err != nil {
		return err
	}
	return n.checkWriters(ctx, 0, true)
}

func bootoutRecoveryJob(expected launchJob, birth string, observe func() (launchJob, string, error), bootout func(string) error, waitExit func(int) error) error {
	now, nowBirth, err := observe()
	if err != nil || now != expected || nowBirth != birth {
		return fmt.Errorf("registered service identity changed before recovery bootout")
	}
	if err := bootout(expected.label); err != nil {
		return err
	}
	return waitExit(expected.pid)
}
