package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/zeroemployeeorg/pomar/internal/seatterm"
	"github.com/zeroemployeeorg/pomar/internal/sessiond"
)

// `pomar session`: named programs on terminals that outlive every client,
// served by this user's session service (docs/sessions.md). Everything but
// attach prints JSON, and every refusal has a fixed exit code, so another
// program can drive a session as well as a person can.

// Exit codes of `pomar session`, beyond 0, 1 and 2.
const (
	exitNoService = 3 // no session service runs for the root: start one with `pomar session serve`
	exitNotFound  = 4 // no session has that name
	exitConflict  = 5 // refused as it stands: the name runs, another client controls it, or the operation is still running
	exitExited    = 6 // the session's program has exited
)

const sessionUsage = `usage:
  pomar session serve [-root DIR]   run this user's session service (in the foreground)
  pomar session new -id OP [-kind K] [-cols C -rows R] [-env K=V]... [-dir D] NAME -- /ABS/PROGRAM ARGS...
  pomar session ls [-json]
  pomar session show NAME           the session's state, as JSON
  pomar session screen [-json] NAME the current screen, as text
  pomar session send -id OP [-enter] [-take] NAME TEXT
  pomar session attach [-view] [-take] NAME
                                    the session's terminal; Ctrl-] detaches, and the program keeps running
  pomar session stop -id OP NAME
Every command takes -root DIR; the root defaults to $POMAR_SESSION_ROOT, or ~/.local/state/pomar/sessions.
`

func sessionCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, sessionUsage)
		return 2
	}
	verb, args := args[0], args[1:]
	fs := flag.NewFlagSet("session "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "", "the session service's root (default $POMAR_SESSION_ROOT, or ~/.local/state/pomar/sessions)")
	op := fs.String("id", "", "the operation's ID: a retry with the same ID returns what it did, and never acts twice")
	var tail []string
	if verb == "new" {
		for i, a := range args {
			if a == "--" {
				args, tail = args[:i], args[i+1:]
				break
			}
		}
	}
	var (
		asJSON = fs.Bool("json", false, "print JSON")
		kind   = fs.String("kind", "program", "the session's kind: a lower-case word (agent, shell, ...)")
		cols   = fs.Uint("cols", 0, "the window's columns (default: this terminal's, or 80)")
		rows   = fs.Uint("rows", 0, "the window's rows (default: this terminal's, or 24)")
		dir    = fs.String("dir", "", "the program's working directory")
		enter  = fs.Bool("enter", false, "end the text with Enter (a carriage return)")
		take   = fs.Bool("take", false, "take control from whoever holds it")
		view   = fs.Bool("view", false, "view only: nothing you type is sent")
		envs   multiFlag
	)
	fs.Var(&envs, "env", "K=V for the program's environment (repeatable); TERM, HOME, PATH and LANG come from yours unless set")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if *root == "" {
		if *root, err = sessiond.DefaultRoot(); err != nil {
			fmt.Fprintln(stderr, "pomar session:", err)
			return 2
		}
	}
	need := func(n int, what string) bool {
		if len(pos) != n {
			fmt.Fprintf(stderr, "pomar session %s: %s\n%s", verb, what, sessionUsage)
			return false
		}
		return true
	}
	needOp := func() bool {
		if *op == "" {
			fmt.Fprintf(stderr, "pomar session %s: -id names the operation, so a retry never acts twice\n", verb)
			return false
		}
		return true
	}
	c := sessiond.NewClient(*root)
	printJSON := func(v any) {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Fprintln(stdout, string(b))
	}
	call := func(method, path string, body, out any) int {
		return sessionExit(verb, *op, c.Do(method, path, body, out), stderr)
	}
	switch verb {
	case "serve":
		if !need(0, "serve takes no arguments") {
			return 2
		}
		return sessionServe(*root, stdout, stderr)
	case "new":
		if !need(1, "new names its session") || !needOp() {
			return 2
		}
		if len(tail) == 0 {
			fmt.Fprintln(stderr, "pomar session new: the program follows --, by its absolute path")
			return 2
		}
		w, h := uint16(80), uint16(24)
		if onTerminal(stdin) {
			if tc, tr, err := ttySize(stdin); err == nil {
				w, h = tc, tr
			}
		}
		if *cols > 0 {
			w = uint16(min(*cols, seatterm.MaxCols))
		}
		if *rows > 0 {
			h = uint16(min(*rows, seatterm.MaxRows))
		}
		req := sessiond.CreateRequest{Operation: *op, Name: pos[0], Kind: *kind, Path: tail[0], Args: tail[1:], Env: sessionEnv(envs), Dir: *dir, Cols: w, Rows: h}
		var out sessiond.Created
		if rc := call("POST", "/v1/sessions", req, &out); rc != 0 {
			return rc
		}
		printJSON(out)
	case "ls":
		if !need(0, "ls takes no arguments") {
			return 2
		}
		var l sessiond.Listing
		if rc := call("GET", "/v1/sessions", nil, &l); rc != 0 {
			return rc
		}
		if *asJSON {
			printJSON(l)
			return 0
		}
		tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tKIND\tSTATE\tSIZE\tCONTROLLER\tVIEWERS\tLAST OUTPUT")
		for _, s := range l.Sessions {
			state := "running"
			if !s.Running && s.ExitCode != nil {
				state = fmt.Sprintf("exited %d", *s.ExitCode)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%dx%d\t%s\t%d\t%s\n", s.Name, s.Kind, state, s.Cols, s.Rows, dash(s.Controller), len(s.Viewers), dash(s.LastOutput))
		}
		tw.Flush()
		for _, u := range l.Unrecovered {
			fmt.Fprintf(stdout, "%s (%s): held by an earlier service, out of this one's reach\n", dash(u.Name), u.ID)
		}
	case "show":
		if !need(1, "show names its session") {
			return 2
		}
		var info json.RawMessage
		if rc := call("GET", "/v1/sessions/"+url.PathEscape(pos[0]), nil, &info); rc != 0 {
			return rc
		}
		printJSON(info)
	case "screen":
		if !need(1, "screen names its session") {
			return 2
		}
		var scr seatterm.ScreenText
		if rc := call("GET", "/v1/sessions/"+url.PathEscape(pos[0])+"/screen", nil, &scr); rc != 0 {
			return rc
		}
		if *asJSON {
			printJSON(scr)
			return 0
		}
		lines := scr.Lines
		for len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1] // the blank rows below the last text
		}
		fmt.Fprintln(stdout, strings.Join(lines, "\n"))
	case "send":
		if !need(2, "send names its session and its text") || !needOp() {
			return 2
		}
		text := pos[1]
		if *enter {
			text += "\r"
		}
		var out sessiond.OpResult
		if rc := call("POST", "/v1/sessions/"+url.PathEscape(pos[0])+"/send", sessiond.SendRequest{Operation: *op, Text: text, Take: *take}, &out); rc != 0 {
			return rc
		}
		printJSON(out)
	case "stop":
		if !need(1, "stop names its session") || !needOp() {
			return 2
		}
		var out sessiond.OpResult
		if rc := call("POST", "/v1/sessions/"+url.PathEscape(pos[0])+"/stop", sessiond.StopRequest{Operation: *op}, &out); rc != 0 {
			return rc
		}
		printJSON(out)
	case "attach":
		if !need(1, "attach names its session") {
			return 2
		}
		return sessionAttach(c, pos[0], *view, *take, stdin, stdout, stderr)
	default:
		fmt.Fprint(stderr, sessionUsage)
		return 2
	}
	return 0
}

// sessionExit maps a call's error to the fixed exit codes, and says what to
// do next.
func sessionExit(verb, op string, err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	fmt.Fprintf(stderr, "pomar session %s: %v\n", verb, err)
	var r *sessiond.Refusal
	switch {
	case errors.Is(err, sessiond.ErrNoService):
		fmt.Fprintln(stderr, "No session service answers for this root. Its owner starts one with `pomar session serve`; see docs/sessions.md.")
		return exitNoService
	case errors.Is(err, sessiond.ErrNoReply):
		if op != "" {
			fmt.Fprintf(stderr, "Ask again with the same -id %s: it returns what the operation did, and never acts twice.\n", op)
		}
		return 1
	case errors.As(err, &r):
		switch r.Kind {
		case sessiond.KindUsage:
			return 2
		case sessiond.KindNotFound:
			return exitNotFound
		case sessiond.KindConflict, sessiond.KindInProgress:
			return exitConflict
		case sessiond.KindExited:
			return exitExited
		}
	}
	return 1
}

func sessionServe(root string, stdout, stderr io.Writer) int {
	s, err := sessiond.Open(root)
	if err != nil {
		fmt.Fprintln(stderr, "pomar session serve:", err)
		if errors.Is(err, sessiond.ErrServing) {
			return exitConflict
		}
		return 1
	}
	defer s.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	b, _ := json.Marshal(map[string]string{"socket": s.Socket(), "root": root, "state": "listening",
		"survives": "clients and dropped connections; not a restart of this service, and not a reboot"})
	ready := func() { fmt.Fprintln(stdout, string(b)) }
	if err := s.Serve(ctx, ready); err != nil {
		fmt.Fprintln(stderr, "pomar session serve:", err)
		return 1
	}
	return 0
}

func sessionAttach(c *sessiond.Client, name string, view, take bool, stdin *os.File, stdout, stderr io.Writer) int {
	st, err := c.Attach(name, view, take)
	if err != nil {
		return sessionExit("attach", "", err, stderr)
	}
	defer st.Close()
	cols, rows := uint16(80), uint16(24)
	var resizes chan [2]uint16
	if onTerminal(stdin) {
		if tc, tr, err := ttySize(stdin); err == nil {
			cols, rows = tc, tr
		}
		restore, err := rawMode(stdin)
		if err != nil {
			fmt.Fprintln(stderr, "pomar session attach:", err)
			return 1
		}
		defer restore()
		resizes = make(chan [2]uint16, 4)
		winch := make(chan os.Signal, 4)
		signal.Notify(winch, syscall.SIGWINCH)
		defer signal.Stop(winch)
		go func() {
			for range winch {
				if tc, tr, err := ttySize(stdin); err == nil {
					resizes <- [2]uint16{tc, tr}
				}
			}
		}()
	}
	// Notices wait until the terminal is back: printed into a program's
	// screen, they would corrupt it.
	var notices []string
	detached, err := sessiond.Pump(st, stdin, stdout, cols, rows, resizes, func(n string) { notices = append(notices, n) })
	if onTerminal(stdin) {
		fmt.Fprint(stdout, "\x1b[0m\x1b[?25h\r\n")
	}
	for _, n := range notices {
		fmt.Fprintf(stderr, "pomar session: %s\r\n", n)
	}
	if err != nil {
		fmt.Fprintln(stderr, "pomar session attach:", err)
		return 1
	}
	if detached {
		fmt.Fprintf(stderr, "Detached from %s; it keeps running.\r\n", name)
	}
	return 0
}

// sessionEnv is a new session's whole environment: TERM, HOME, PATH and
// LANG from the caller's, then each -env, which wins.
func sessionEnv(set []string) []string {
	env := map[string]string{"TERM": "xterm-256color"}
	order := []string{"TERM"}
	for _, k := range []string{"TERM", "HOME", "PATH", "LANG"} {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			if _, seen := env[k]; !seen {
				order = append(order, k)
			}
			env[k] = v
		}
	}
	for _, kv := range set {
		k, v, _ := strings.Cut(kv, "=")
		if _, seen := env[k]; !seen {
			order = append(order, k)
		}
		env[k] = v
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+env[k])
	}
	return out
}

// parseMixed parses flags wherever they come among the positional
// arguments.
func parseMixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	if !strings.Contains(v, "=") || strings.HasPrefix(v, "=") {
		return errors.New("want K=V")
	}
	*m = append(*m, v)
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
