package main

import (
	"github.com/zeroemployeeorg/pomar/internal/agentenv"
	"slices"
	"strings"
	"testing"
)

func TestCodexSeatUsesGuestOnlyEnvironmentAndItsOwnSupervisor(t *testing.T) {
	env := strings.Join(codexSeatEnv(), "\n")
	for _, bad := range []string{"GH_TOKEN", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "CLAUDE_CONFIG_DIR"} {
		if strings.Contains(env, bad) {
			t.Fatal("host or other provider config inherited")
		}
	}
	if !strings.Contains(env, "CODEX_HOME=/pomar/job/.codex") {
		t.Fatal("guest home missing")
	}
	args := codexTmuxEnsure("example", "/opt/codex", "/pomar/guest", "/work", &agentenv.SeatLaunch{})
	i := slices.Index(args, "--")
	if i < 0 || args[i+1] != "/pomar/guest" || args[i+2] != "codex-seat-supervisor" || slices.Contains(args[:i], "/opt/codex") {
		t.Fatal("tmux starts actor directly", args)
	}
}

func TestGuestLaunchRequiresCompleteExactPolicy(t *testing.T) {
	good := `{"sandbox":"workspace-write","approvals":"never","network_access":true,"model":"fixture-model","effort":"high","cwd":"/work"}`
	if _, err := parseCodexLaunch(good); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", `{}`, good + `{}`, strings.Replace(good, `"cwd":"/work"`, `"cwd":"/other"`, 1), strings.Replace(good, `"cwd":"/work"`, `"cwd":"/work","arbitrary_command":"shell"`, 1)} {
		if _, err := parseCodexLaunch(raw); err == nil {
			t.Fatal("invalid guest launch accepted")
		}
	}
}
