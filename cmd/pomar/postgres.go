package main

// sow: pomar-SOW-87 rev27 (seven-path grant in revisions22/23).
import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/postgres"
)

type postgresValues []string

func (v *postgresValues) String() string     { return strings.Join(*v, ",") }
func (v *postgresValues) Set(s string) error { *v = append(*v, s); return nil }

func postgresCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "run" {
		fmt.Fprintln(stderr, "usage: pomar postgres run -work-root OWNED_0700_DIR -tools MANIFEST -tools-sha256 HEX -cwd DIR [-whole 5m -startup 30s -stop 10s -log-bytes 8388608] [-extension NAME@VERSION] [-role-profile NAME] [-env KEY=VALUE] -- /absolute/GATE [ARGS...]")
		return 2
	}
	f := flag.NewFlagSet("postgres run", flag.ContinueOnError)
	f.SetOutput(stderr)
	var c postgres.Config
	var extensions, env postgresValues
	f.StringVar(&c.WorkRoot, "work-root", "", "existing owned0700 work root")
	f.StringVar(&c.Manifest, "tools", "", "complete pinned tool manifest")
	f.StringVar(&c.ManifestSHA256, "tools-sha256", "", "independently selected manifest SHA256")
	f.StringVar(&c.GateDir, "cwd", "", "existing owned gate working directory")
	f.DurationVar(&c.Whole, "whole", 5*time.Minute, "whole invocation deadline, including preparation and shutdown")
	f.DurationVar(&c.Startup, "startup", 30*time.Second, "maximum per initialization/readiness stage within whole deadline")
	f.DurationVar(&c.Stop, "stop", 10*time.Second, "shutdown reserve inside whole deadline")
	f.Int64Var(&c.LogBytes, "log-bytes", 8<<20, "aggregate retained server/stdout/stderr bound")
	f.StringVar(&c.RoleProfile, "role-profile", "", "reviewed role profile name present in pinned manifest")
	f.Var(&extensions, "extension", "required exact NAME@VERSION; repeatable")
	f.Var(&env, "env", "explicit PATH/LANG/LC_ALL/TZ/CI only; repeatable; no inherited environment")
	if e := f.Parse(args[1:]); e != nil {
		return 2
	}
	c.Gate = f.Args()
	c.Env = env
	c.Extensions = map[string]string{}
	for _, x := range extensions {
		n, v, ok := strings.Cut(x, "@")
		if !ok || n == "" || v == "" || c.Extensions[n] != "" {
			fmt.Fprintln(stderr, "extension requires unique NAME@VERSION")
			return 2
		}
		c.Extensions[n] = v
	}
	if c.WorkRoot == "" || c.Manifest == "" || c.ManifestSHA256 == "" || c.GateDir == "" || len(c.Gate) == 0 {
		fmt.Fprintln(stderr, "explicit work-root, tools, tools-sha256, cwd and gate required")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	r, e := postgres.Run(ctx, c)
	if e != nil && r.Error == "" {
		r.Error = e.Error()
	}
	if encErr := json.NewEncoder(stdout).Encode(r); encErr != nil {
		fmt.Fprintln(stderr, "result output failed; inspect retained invocation metadata")
		return 1
	}
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 1
	}
	if !r.CleanupConfirmed || !r.LogsComplete || r.GateExit == nil || *r.GateExit != 0 {
		fmt.Fprintln(stderr, "complete successful gate and cleanup not established")
		return 1
	}
	return 0
}
