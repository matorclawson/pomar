package serviceupgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// current refuses unknown bytes, unsafe custody and a pair that could both
// auto-load on reboot. An empty result is a recoverable interrupted migration.
func (p launchPlists) current() (string, error) {
	if err := directory(p.dir, p.uid, 0); err != nil {
		return "", err
	}
	var current string
	for _, label := range []string{legacyLabel, neutralLabel} {
		_, err := os.Lstat(p.path(label))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if current != "" {
			return "", fmt.Errorf("both service plists are installed")
		}
		pin := p.manifest.Retained["plist"]
		if label != p.manifest.serviceLabel(false) {
			if !p.manifest.migrating() {
				return "", fmt.Errorf("unexpected service plist")
			}
			pin = *p.manifest.Identifiers.TargetPlist
		}
		if _, err := pinnedOwnedFile(p.path(label), pin, p.uid); err != nil {
			return "", fmt.Errorf("installed %s plist binding differs: %w", label, err)
		}
		current = label
	}
	return current, nil
}

func (p launchPlists) require(label string) error {
	current, err := p.current()
	if err != nil {
		return err
	}
	if current != label {
		return fmt.Errorf("installed service plist differs from %s", label)
	}
	return nil
}

// The caller proves both launchd labels absent before changing either file.
// Remove the installed plist before touching binaries and publish the
// replacement only after the new binary/record set is complete.
func (p launchPlists) remove() error {
	current, err := p.current()
	if err != nil || current == "" {
		return err
	}
	if err := os.Remove(p.path(current)); err != nil {
		return err
	}
	return syncDirectory(p.dir)
}

func (p launchPlists) publish(label string, data []byte, mode os.FileMode) error {
	if !p.manifest.migrating() || (label != legacyLabel && label != neutralLabel) {
		return fmt.Errorf("unsupported launch plist publication")
	}
	if err := p.require(""); err != nil {
		return err
	}
	pin := p.manifest.Retained["plist"]
	if label == neutralLabel {
		pin = *p.manifest.Identifiers.TargetPlist
	}
	if digest(data) != pin.SHA256 || int64(len(data)) != pin.Bytes {
		return fmt.Errorf("replacement service plist bytes differ")
	}
	if err := durableWriteOwned(p.path(label), data, mode, p.uid); err != nil {
		return err
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
	oldPath := p.path(legacyLabel)
	if n.rollback {
		if _, err := p.current(); err != nil {
			return err
		}
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

func (n *Native) currentService(ctx context.Context) (string, error) {
	raw, err := command(ctx, nil, "/bin/launchctl", "list")
	if err != nil {
		return "", err
	}
	label, err := loadedService(raw)
	if err != nil {
		return "", err
	}
	if label == "" {
		return "", fmt.Errorf("service is not loaded")
	}
	if err := n.launchPlists().require(label); err != nil {
		return "", err
	}
	return label, nil
}

func loadedService(raw []byte) (string, error) {
	rows := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if strings.Join(strings.Fields(rows[0]), " ") != "PID Status Label" {
		return "", fmt.Errorf("launchd inventory incomplete")
	}
	var label string
	for _, row := range rows[1:] {
		f := strings.Fields(row)
		if len(f) != 3 {
			return "", fmt.Errorf("launchd inventory malformed")
		}
		if f[2] == legacyLabel || f[2] == neutralLabel {
			if label != "" {
				return "", fmt.Errorf("multiple Pomar services loaded")
			}
			label = f[2]
		}
	}
	return label, nil
}
