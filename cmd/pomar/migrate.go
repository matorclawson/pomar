package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zeroemployeeorg/pomar/internal/seatmigration"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

type migrationOutput struct{ bytes.Buffer }

func (b *migrationOutput) Write(p []byte) (int, error) {
	if len(p) > seatmigration.MaxInventory-b.Len() {
		return 0, errors.New("tmux inventory exceeds bound")
	}
	return b.Buffer.Write(p)
}
func migrationRead(path string, out any) error {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > seatmigration.MaxInventory {
		return errors.New("migration JSON requires a bounded regular file")
	}
	d := json.NewDecoder(io.LimitReader(f, seatmigration.MaxInventory+1))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing or oversized JSON")
	}
	return nil
}
func migrateCmd(args []string, out, errout io.Writer) int {
	if len(args) == 0 {
		return 2
	}
	fs := flag.NewFlagSet("migrate "+args[0], flag.ContinueOnError)
	fs.SetOutput(errout)
	socket := fs.String("socket", "", "explicit existing tmux socket")
	binary := fs.String("tmux-bin", "", "absolute existing tmux executable")
	inventory := fs.String("inventory", "", "saved inventory JSON")
	manifest := fs.String("manifest", "", "explicit seat mapping and capacity JSON")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return 2
	}
	var value any
	var e error
	switch args[0] {
	case "inventory":
		if !filepath.IsAbs(*socket) || !filepath.IsAbs(*binary) {
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, *binary, "-S", *socket, "list-panes", "-a", "-F", seatmigration.Format)
		var buf migrationOutput
		cmd.Stdout = &buf
		cmd.Stderr = io.Discard
		if e = cmd.Run(); e == nil {
			var inv seatmigration.Inventory
			inv, e = seatmigration.Parse(*socket, buf.Bytes())
			value = struct {
				seatmigration.Inventory
				Digest string `json:"inventory_sha256"`
			}{inv, seatmigration.Digest(inv)}
		}
	case "plan":
		if *inventory == "" || *manifest == "" {
			return 2
		}
		var inv struct {
			seatmigration.Inventory
			Digest string `json:"inventory_sha256"`
		}
		var m seatmigration.Manifest
		if e = migrationRead(*inventory, &inv); e == nil {
			e = migrationRead(*manifest, &m)
		}
		if e == nil && inv.Digest != seatmigration.Digest(inv.Inventory) {
			e = errors.New("inventory digest mismatch")
		}
		if e == nil {
			value, e = seatmigration.Build(inv.Inventory, m)
		}
	default:
		return 2
	}
	if e != nil {
		fmt.Fprintln(errout, "pomar migrate:", e)
		return 1
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if enc.Encode(value) != nil {
		return 1
	}
	return 0
}
