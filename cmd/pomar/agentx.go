package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/manager"
)

// The agent experience: what lets a program, an agent or a script, use
// Pomar without reading English output. Every command an agent needs
// prints JSON, has a fixed exit code, and says what to do next when it
// can't go on. Nothing here depends on which agent is calling.

// Exit codes of `pomar run -wait`, beyond the job's own. They are listed by
// `pomar help -json`, and are stable: an agent may branch on them.
const (
	exitWaitGaveUp = 75  // -timeout passed and the job is still running; it was not stopped
	exitTimedOut   = 124 // the job was stopped by its class's time limit
	exitPomar      = 125 // Pomar couldn't run the job to its end: it failed, or its helper was lost
	exitStopped    = 143 // the job was stopped on request
)

// noManager is what every command that needs a manager says when none is
// selected. Pomar never guesses one.
const noManager = "no manager selected: set POMAR_SOCKET to the control socket your host owner gave you, or pass -socket PATH (the owner on their own host may pass -root DIR). Pomar never guesses one; `pomar doctor` checks the one you name."

// waitFor polls an attempt until it ends, or until timeout (0: no limit).
// It never stops the attempt.
func waitFor(c *manager.Client, id string, timeout time.Duration) (manager.Entry, bool, error) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	interval := 250 * time.Millisecond
	for {
		var e manager.Entry
		if err := c.Do("GET", "/v1/attempts/"+id, nil, &e); err != nil {
			return e, false, err
		}
		if e.Terminal() {
			return e, true, nil
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return e, false, nil
		}
		time.Sleep(interval)
		if interval < 2*time.Second {
			interval *= 2
		}
	}
}

// jobExitCode is the exit code `pomar run -wait` returns for an ended
// attempt: the job's own when it exited, and Pomar's fixed codes when it
// didn't.
func jobExitCode(e manager.Entry) int {
	switch e.State {
	case manager.StateExited:
		if e.ExitCode != nil {
			if c := *e.ExitCode; c >= 0 && c <= 255 {
				return c
			}
		}
		return exitPomar
	case manager.StateTimedOut:
		return exitTimedOut
	case manager.StateStopped:
		return exitStopped
	}
	return exitPomar
}

// notEnded explains a log or result asked for before the job ended.
func notEnded(c *manager.Client, id string, stderr io.Writer) bool {
	var e manager.Entry
	if c.Do("GET", "/v1/attempts/"+id, nil, &e) != nil || e.Terminal() {
		return false
	}
	fmt.Fprintf(stderr, "%s hasn't ended yet (state %s). Wait for it with `pomar wait -id %s`, then ask again.\n", id, e.State, id)
	return true
}

// command is one entry of the machine-readable catalogue.
type command struct {
	Name    string   `json:"name"`
	Summary string   `json:"summary"`
	Usage   string   `json:"usage"`
	Output  string   `json:"output"`
	Notes   []string `json:"notes,omitempty"`
}

// helpCatalogue is what `pomar help -json` prints: enough for an agent to use
// Pomar without parsing prose.
func helpCatalogue() map[string]any {
	return map[string]any{
		"schema":  "pomar.help/v1",
		"version": version,
		"source":  sourceCommit,
		"select_manager": map[string]any{
			"env":     "POMAR_SOCKET",
			"flag":    "-socket PATH",
			"owner":   "-root DIR (the host owner, on their own host)",
			"guessed": false,
			"check":   "pomar doctor -json",
		},
		"loop": []string{
			"pomar doctor -json",
			"pomar status",
			"pomar run -wait -id ID -class CLASS -- COMMAND...",
			"pomar logs -id ID",
			"pomar attempt result -id ID",
		},
		"commands": []command{
			{"doctor", "Check this client, its bundled tools and the selected manager", "pomar doctor [-socket PATH] [-json]",
				"text, or a JSON array of {name, ok, skipped, detail, next}", []string{"exit 0 when everything needed is usable, 1 otherwise"}},
			{"status", "The manager's classes, capacity and admission limits", "pomar status [-socket PATH]", "JSON", []string{"the classes you may run are under classes[].name"}},
			{"run", "Start a job in a fresh micro-VM", "pomar run [-wait [-timeout D]] -id ID [-class CLASS] [-mirror NAME -ref REF [-sha SHA]] [-input NAME=PATH]... [-output NAME]... -- COMMAND...",
				"JSON: the attempt record (at admission, or with -wait once it ended)",
				[]string{"IDs are unique: reusing one is refused (409)", "without -wait, success means admitted, not finished",
					"with -wait, the exit code is the job's own, or one of the codes in exit_codes"}},
			{"wait", "Wait for an admitted job to end", "pomar wait -id ID [-timeout D]", "JSON: the attempt record once it ended", []string{"the same exit codes as run -wait"}},
			{"jobs", "List attempts", "pomar jobs [-socket PATH]", "JSON array of attempt records", nil},
			{"attempt get", "One attempt's record, including its state", "pomar attempt get -id ID", "JSON", nil},
			{"attempt progress", "A running attempt's phase and bounded provisional output", "pomar attempt progress -id ID", "JSON", []string{"older managers don't expose it"}},
			{"logs", "An ended job's output, checked against its result", "pomar logs -id ID [-public-key KEY] [-o PATH]", "the log's bytes", []string{"refused, with what to do, while the job is still running"}},
			{"attempt result", "The signed result document", "pomar attempt result -id ID", "JSON, exactly as signed", []string{"verify it with the owner's independently retained public key"}},
			{"attempt stop", "Stop a running job", "pomar attempt stop -id ID", "JSON", nil},
			{"seats", "List declared development seats", "pomar seats [-root DIR]", "JSON (a numbered menu on a terminal)", nil},
			// session: POMAR-CC's entry, for Pomar to fold into the catalogue's release form.
			{"session", "Named programs on terminals that outlive every client, from this user's session service",
				"pomar session serve|new -id OP [-state] NAME -- /ABS/PROGRAM...|ls [-json]|show NAME|screen [-json] NAME|send -id OP [-enter] [-session ID] [-epoch N] [-when-ready] [-accept-wait D] NAME [--] TEXT|attach [-view] [-take] NAME|stop -id OP NAME",
				"JSON (attach is the terminal; screen prints text, or JSON with -json)",
				[]string{"exit 3: no session service for the root; 4: no such name; 5: refused as it stands (a running name, another controller, an operation still running); 6: the program exited; 7: stale (the session changed since you read it); 8: unsupported (-when-ready without a state channel); 9: not ready in time",
					"-id makes new, send and stop once-only: a retry with the same ID returns what it did, and never acts twice",
					"a send's reply tells queued, written and accepted apart; accepted only from the session's adapter",
					"agent state is adapter-reported, never read off the screen; unknown without an adapter",
					"native execution under your OS user, not a guest; it doesn't survive a restart of the service or a reboot", "docs/sessions.md, docs/sessions-protocol.md"}},
			{"version", "Client version and source commit", "pomar version", "text", nil},
		},
		"exit_codes": map[string]string{
			"0":     "success (with run -wait: the job exited 0)",
			"1":     "the command failed; stderr says why and what to do",
			"2":     "usage: a flag or argument is wrong",
			"75":    "run -wait gave up after -timeout; the job is still running and was not stopped",
			"124":   "run -wait: the job was stopped by its class's time limit",
			"125":   "run -wait: Pomar couldn't run the job to its end (failed, or its helper was lost); see the record's reason",
			"143":   "run -wait: the job was stopped on request",
			"other": "run -wait: the job's own exit code",
		},
		"never": []string{
			"guess a socket or data root",
			"use sudo or widen a socket's permissions when refused: that is the host owner's decision",
			"treat admission as success: wait for the end, then read and verify the result",
		},
		"docs": "AGENTS.md, docs/operations.md",
	}
}

func helpJSON(stdout io.Writer) int {
	b, _ := json.MarshalIndent(helpCatalogue(), "", "  ")
	fmt.Fprintln(stdout, string(b))
	return 0
}
