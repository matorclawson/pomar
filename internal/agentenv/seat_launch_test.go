package agentenv

import "testing"

func TestSeatLaunchRefusesMissingOrContradictoryPolicy(t *testing.T) {
	network := true
	good := SeatLaunch{Sandbox: "workspace-write", Approvals: "never", NetworkAccess: &network, Model: "fixture-model", Effort: "high", CWD: "/work"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (*SeatLaunch)(nil).Validate(); err == nil {
		t.Fatal("missing launch accepted")
	}
	for name, change := range map[string]func(*SeatLaunch){"readonly network contradiction": func(l *SeatLaunch) { l.Sandbox = "read-only" }, "unproven effort": func(l *SeatLaunch) { l.Effort = "max" }, "missing network": func(l *SeatLaunch) { l.NetworkAccess = nil }, "unknown sandbox": func(l *SeatLaunch) { l.Sandbox = "automatic" }, "unknown approvals": func(l *SeatLaunch) { l.Approvals = "auto" }, "missing model": func(l *SeatLaunch) { l.Model = "" }, "different source": func(l *SeatLaunch) { l.CWD = "/other" }, "shell model": func(l *SeatLaunch) { l.Model = "$(command)" }, "impossible disabled network": func(l *SeatLaunch) { n := false; l.NetworkAccess = &n; l.Sandbox = "danger-full-access" }} {
		l := good
		change(&l)
		if err := l.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
