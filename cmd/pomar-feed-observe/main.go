// Command pomar-feed-observe checks actual release/1 bytes and emits a byte
// observation. It never reads a key, signs, publishes, or claims build success.
package main

import (
	"flag"
	"fmt"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedinput"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedobserver"
	"io"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if e := run(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

type artifactRoot interface {
	releasefeedinput.Root
	Open(string) (*os.File, error)
	Close() error
}

func run(args []string, out io.Writer) error {
	return runUsingRoot(args, out, func(path string) (artifactRoot, error) { return os.OpenRoot(path) })
}
func runUsingRoot(args []string, out io.Writer, openRoot func(string) (artifactRoot, error)) error {
	f := flag.NewFlagSet("pomar-feed-observe", flag.ContinueOnError)
	dir := f.String("inputs", "", "received artifact directory")
	head := f.String("head", "", "independently received full source commit")
	tree := f.String("tree", "", "independently received full source tree")
	owner := f.String("owner-message", "", "source owner receipt message")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || !filepath.IsAbs(*dir) {
		return fmt.Errorf("absolute input directory and no positional arguments required")
	}
	before, e := os.Lstat(*dir)
	if e != nil || !before.IsDir() {
		return fmt.Errorf("real input directory required")
	}
	root, e := openRoot(*dir)
	if e != nil {
		return e
	}
	defer root.Close()
	listing, e := root.Open(".")
	if e != nil {
		return e
	}
	defer listing.Close()
	opened, e := listing.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return fmt.Errorf("input directory changed")
	}
	entries, e := listing.ReadDir(19)
	if e != nil && e != io.EOF {
		return e
	}
	if len(entries) > 18 {
		return fmt.Errorf("too many input files")
	}
	files := map[string][]byte{}
	for _, entry := range entries {
		name := entry.Name()
		limit := releasefeedinput.MaxBytes
		switch name {
		case "release.json":
			limit = 131072
		case "SHA256SUMS":
			limit = 16384
		}
		raw, e := releasefeedinput.ReadRegular(root, name, limit)
		if e != nil {
			return e
		}
		files[name] = raw
	}
	receipt, e := releasefeedobserver.Observe(releasefeedobserver.Context{Head: *head, Tree: *tree, SourceOwnerMessage: *owner, ObservedAt: time.Now()}, files)
	if e != nil {
		return e
	}
	_, e = fmt.Fprintln(out, string(receipt))
	return e
}
