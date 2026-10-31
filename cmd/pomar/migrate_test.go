package main

import (
	"github.com/zeroemployeeorg/pomar/internal/seatmigration"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationReadRefusesValidPrefixBeyondByteBound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	if err := os.WriteFile(path, []byte(`{}`+strings.Repeat(" ", seatmigration.MaxInventory)+`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := migrationRead(path, &value); err == nil {
		t.Fatal("oversized valid prefix accepted")
	}
}

func TestMigrationReadRejectsRedirectAndTrailingData(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "input.json")
	link := filepath.Join(dir, "link.json")
	if err := os.WriteFile(file, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := migrationRead(link, &value); err == nil {
		t.Fatal("redirect accepted")
	}
	if err := migrationRead(file, &value); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(`{} {}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrationRead(file, &value); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
