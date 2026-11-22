package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rodriveracom/pomar/internal/distribution"
)

func TestSwiftLicenseInventoryCoversTrackedLock(t *testing.T) {
	if _, err := swiftLicensePins("../.."); err != nil {
		t.Fatal(err)
	}
}

func TestBuiltBundleContainsEveryLockedSwiftLicenseAndNotice(t *testing.T) {
	source, bins, checkouts := t.TempDir(), t.TempDir(), t.TempDir()
	rootName := "pomar-v0.1.0-darwin-arm64"
	out := filepath.Join(t.TempDir(), "release")
	licenses := map[string]map[string]string{
		"alpha": {
			"LICENSE": "alpha license\n", "NOTICE": "alpha notice\n", "NOTICE.txt": "alpha attribution\n",
			"Sources/CDep/LICENSE": "nested license\n",
		},
		"beta": {
			"LICENSE": "beta license with no final newline",
			"NOTICES": "beta notices\n", "NOTICES.txt": "beta attributions with no final newline",
		},
	}
	var lock struct {
		Pins []swiftPin
	}
	table := strings.Join(swiftLicenseHeader, "\t") + "\n"
	for _, identity := range []string{"alpha", "beta"} {
		files := licenses[identity]
		checkout := filepath.Join(checkouts, identity)
		for name, data := range files {
			writeDistFixture(t, filepath.Join(checkout, name), []byte(data))
		}
		gitFixture(t, checkout, "init", "--quiet", "--object-format=sha1")
		gitFixture(t, checkout, "add", ".")
		gitFixture(t, checkout, "-c", "user.name=Pomar Fixture", "-c", "user.email=pomar@example.invalid",
			"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "license fixture")
		revision := gitFixture(t, checkout, "rev-parse", "HEAD")
		pin := swiftPin{Identity: identity, Location: "https://github.com/example/" + identity + ".git"}
		pin.State.Version, pin.State.Revision = "1.0.0", revision
		lock.Pins = append(lock.Pins, pin)
		table += fmt.Sprintf("%s\t1.0.0\t%s\tfixture\t%x\thttps://raw.githubusercontent.com/example/%s/%s/LICENSE\n",
			identity, revision, sha256.Sum256([]byte(files["LICENSE"])), identity, revision)
	}
	raw, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	writeDistFixture(t, filepath.Join(source, "host", "Package.resolved"), raw)
	for _, name := range distribution.Files {
		switch {
		case name == distribution.SwiftLicenseFile:
		case name == swiftLicenseTable:
			writeDistFixture(t, filepath.Join(source, name), []byte(table))
		case strings.HasPrefix(name, "bin/"):
			writeDistFixture(t, filepath.Join(bins, filepath.Base(name)), executableHeader(strings.HasSuffix(name, "linux-arm64")))
		default:
			writeDistFixture(t, filepath.Join(source, name), []byte("fixture "+name+"\n"))
		}
	}
	writeDistFixture(t, filepath.Join(source, "tools", "install.sh"), []byte("#!/bin/sh\n"))
	if err := run([]string{"-version", "v0.1.0", "-commit", strings.Repeat("a", 40),
		"-source", source, "-bin-dir", bins, "-swift-checkouts", checkouts, "-out", out}); err != nil {
		t.Fatal(err)
	}
	bundle, err := os.Open(filepath.Join(out, rootName+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	gz, err := gzip.NewReader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	got := make(map[string][]byte)
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		text, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		got[strings.TrimPrefix(header.Name, rootName+"/")] = text
	}
	if string(got["NOTICE"]) != "fixture NOTICE\n" || string(got[swiftLicenseTable]) != table {
		t.Fatal("project notice or license inventory missing from archive")
	}
	combined := got[distribution.SwiftLicenseFile]
	for identity, files := range licenses {
		for path, text := range files {
			if !bytes.Contains(combined, []byte("\n--- "+identity+"/"+path+" ---\n"+text+"\n")) {
				t.Errorf("archive lacks exact text for %s/%s", identity, path)
			}
		}
	}
	var manifest distribution.Manifest
	if err := json.Unmarshal(got["release.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != distribution.Schema || manifest.Files[distribution.SwiftLicenseFile].SHA256 != fmt.Sprintf("%x", sha256.Sum256(combined)) {
		t.Fatal("manifest did not bind the archived license material")
	}

	lines := strings.Split(table, "\n")
	badHash := strings.Replace(table, fmt.Sprintf("%x", sha256.Sum256([]byte(licenses["alpha"]["LICENSE"]))), strings.Repeat("0", 64), 1)
	writeDistFixture(t, filepath.Join(source, swiftLicenseTable), []byte(badHash))
	if _, err := collectSwiftLicenses(source, checkouts); err == nil || !strings.Contains(err.Error(), "license digest differs") {
		t.Fatalf("wrong license digest accepted: %v", err)
	}
	writeDistFixture(t, filepath.Join(source, swiftLicenseTable), []byte(strings.Join(lines[:2], "\n")+"\n"))
	if _, err := collectSwiftLicenses(source, checkouts); err == nil || !strings.Contains(err.Error(), "every locked package") {
		t.Fatalf("missing pin accepted: %v", err)
	}
}

func writeDistFixture(t *testing.T, file string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func gitFixture(t *testing.T, checkout string, args ...string) string {
	t.Helper()
	out, err := swiftGit(checkout, args...)
	if err != nil {
		t.Fatalf("fixture git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// The packager inspects file headers only. These fixtures are never executed.
func executableHeader(linux bool) []byte {
	if linux {
		header := make([]byte, 64)
		copy(header, []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
		binary.LittleEndian.PutUint16(header[16:], uint16(elf.ET_EXEC))
		binary.LittleEndian.PutUint16(header[18:], uint16(elf.EM_AARCH64))
		binary.LittleEndian.PutUint32(header[20:], uint32(elf.EV_CURRENT))
		binary.LittleEndian.PutUint16(header[52:], uint16(len(header)))
		return header
	}
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[0:], macho.Magic64)
	binary.LittleEndian.PutUint32(header[4:], uint32(macho.CpuArm64))
	binary.LittleEndian.PutUint32(header[12:], uint32(macho.TypeExec))
	return header
}
