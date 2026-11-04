// Command pomar-feed-observe checks actual release/1 bytes and emits a byte
// observation. It never reads a key, signs, publishes, or claims build success.
package main

import (
	"flag"
	"fmt"
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
func run(args []string, out io.Writer) error {
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
	root, e := os.OpenRoot(*dir)
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
		info, e := root.Lstat(name)
		if e != nil || !info.Mode().IsRegular() || info.Size() > releasefeedobserver.MaxArtifactBytes {
			return fmt.Errorf("input leaf invalid")
		}
		file, e := root.Open(name)
		if e != nil {
			return e
		}
		actual, e := file.Stat()
		if e != nil || !os.SameFile(info, actual) {
			file.Close()
			return fmt.Errorf("input changed")
		}
		raw, e := io.ReadAll(io.LimitReader(file, releasefeedobserver.MaxArtifactBytes+1))
		closeErr := file.Close()
		if e != nil || closeErr != nil || len(raw) > releasefeedobserver.MaxArtifactBytes {
			return fmt.Errorf("input read incomplete")
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
