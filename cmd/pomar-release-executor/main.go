// The first source increment exposes no live executor until its protected
// providers, shared component and activation receipts have been received.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
)

func run(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("pomar-release-executor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", "", "protected owner configuration")
	event := fs.String("event", "", "authenticated gold-main observation")
	if fs.Parse(args) != nil || fs.NArg() != 0 || !filepath.IsAbs(*config) || !filepath.IsAbs(*event) {
		return 2
	}
	// Do not open caller-selected paths, launch anything, or manufacture trust
	// while no actual protected configuration/provider has been installed.
	_ = json.NewEncoder(out).Encode(map[string]string{
		"status": "held",
		"reason": "private_executor_bindings_unavailable",
	})
	return 20
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}
