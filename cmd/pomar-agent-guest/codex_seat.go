package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/agentenv"
	"github.com/zeroemployeeorg/pomar/internal/codexseat"
	"github.com/zeroemployeeorg/pomar/internal/seatterm"
)

const codexStateDir = "/var/lib/pomar-agent/codex-seat"
const codexTmuxDir = "/run/pomar-codex-seat"
const codexTmuxSocket = codexTmuxDir + "/tmux.sock"
const codexTmuxConfig = codexTmuxDir + "/tmux.conf"

// Custodian terminal has no command bindings, user config, environment update,
// or usable shell. Only the fixed supervisor command can run in its one pane.
const codexCustodianTmuxConfig = `set-option -g prefix None
set-option -g prefix2 None
set-option -g default-shell /bin/false
set-option -g update-environment ""
set-option -g mouse off
unbind-key -a
unbind-key -a -T root
unbind-key -a -T copy-mode
unbind-key -a -T copy-mode-vi
`

func codexCustodianEnv() []string {
	return []string{"HOME=/root", "PATH=/usr/bin:/bin", "TERM=xterm-256color", "LANG=C.UTF-8"}
}
func codexTmuxHas() []string {
	return []string{seatTmux, "-f", codexTmuxConfig, "-S", codexTmuxSocket, "has-session", "-t", seatSession}
}
func codexSeatEnv() []string {
	return []string{"HOME=" + seatHome, "CODEX_HOME=" + seatHome + "/.codex", "PATH=/opt/pomar-codex/codex-path:/pomar/job/.local/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin", "TERM=xterm-256color", "LANG=C.UTF-8", "HTTPS_PROXY=http://127.0.0.1:7072", "HTTP_PROXY=http://127.0.0.1:7072", "ALL_PROXY=http://127.0.0.1:7072", "GOPROXY=http://127.0.0.1:7070", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly"}
}

func codexTmuxEnsure(seat, binary, self, workspace string, launch *agentenv.SeatLaunch) []string {
	data, _ := json.Marshal(launch)
	return []string{seatTmux, "-f", codexTmuxConfig, "-S", codexTmuxSocket, "new-session", "-d", "-s", seatSession, "-x", "200", "-y", "50", "--", self, "codex-seat-supervisor", "-seat", seat, "-codex", binary, "-workspace", workspace, "-codex-launch", string(data)}
}

func runCodexSeat(store *agentenv.Store, seat, binary, version, workspace, socket string, launch *agentenv.SeatLaunch) error {
	if err := launch.Validate(); err != nil {
		return err
	}
	if launch.CWD != workspace {
		return errors.New("declared cwd differs from guest source")
	}
	if !seatName.MatchString(seat) || version != codexseat.Version || !filepath.IsAbs(binary) || !filepath.IsAbs(workspace) {
		return errors.New("Codex seat requires a valid seat, pinned version and absolute guest paths")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("Codex seat broker requires the VM custodian")
	}
	for _, dir := range []string{codexTmuxDir, codexStateDir} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err = codexseat.CheckCustodianDirectory(dir); err != nil {
			return err
		}
	}
	if err = codexseat.CheckCustodianExecutable(seatTmux); err != nil {
		return err
	}
	if err = codexseat.CheckCustodianExecutable(self); err != nil {
		return err
	}
	// Never read a coding-user tmux config as root.
	if err = os.WriteFile(codexTmuxConfig, []byte(codexCustodianTmuxConfig), 0600); err != nil {
		return err
	}
	command := func(argv []string) *exec.Cmd {
		c := exec.Command(argv[0], argv[1:]...)
		c.Env = codexCustodianEnv()
		c.Dir = "/"
		return c
	}
	ensure := func() error {
		if command(codexTmuxHas()).Run() == nil {
			return nil
		}
		if err := command(codexTmuxEnsure(seat, binary, self, workspace, launch)).Run(); err != nil {
			return errors.New("Codex root supervisor did not start; inspect guest custody")
		}
		return nil
	}
	attach := seatterm.Command{Path: seatTmux, Args: []string{"-f", codexTmuxConfig, "-S", codexTmuxSocket, "attach-session", "-t", seatSession}, Env: codexCustodianEnv(), Dir: "/", UID: 0, GID: 0}
	route, err := seatterm.NewRoute(seatBinding(store), ensure, attach)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return err
	}
	if _, err = os.Lstat(socket); err == nil {
		return errors.New("guest broker socket exists; replacement refused")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	// Authentication is not inferred from the presence of a credentials file.
	// The TUI performs its own guest login; protocol login remains app-server's.
	handler := http.NewServeMux()
	handler.Handle("/", seatHandler(store, route, func() bool { return false }))
	handler.HandleFunc("GET /v1/codex/startup", func(w http.ResponseWriter, r *http.Request) {
		s := codexseat.Supervisor{Seat: seat, Binary: binary, Home: seatHome + "/.codex", StateDir: codexStateDir, Workspace: workspace, Launch: launch, Env: codexSeatEnv()}
		info, e := s.InspectStartup()
		if e != nil {
			http.Error(w, "startup inspection held", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})
	handler.HandleFunc("GET /v1/codex/fence", func(w http.ResponseWriter, r *http.Request) {
		s := codexseat.Supervisor{StateDir: codexStateDir}
		info, e := s.InspectFence()
		if e != nil {
			http.Error(w, "fence observation unavailable", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})
	handler.HandleFunc("POST /v1/codex/startup/abandon", func(w http.ResponseWriter, r *http.Request) {
		var req codexseat.ResetRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || dec.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid reset request", 400)
			return
		}
		launchRecord := codexseat.Supervisor{Seat: seat, Binary: binary, Home: seatHome + "/.codex", StateDir: codexStateDir, Workspace: workspace, Launch: launch, Env: codexSeatEnv()}
		receipt, e := launchRecord.AbandonStart(req, "/var/lib/pomar-agent/codex-start-resets")
		if e != nil {
			http.Error(w, "original unbound startup remains held", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(receipt)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	return server.Serve(ln)
}

func runCodexSeatSupervisor() error {
	fs := flag.NewFlagSet("codex-seat-supervisor", flag.ContinueOnError)
	launchRaw := fs.String("codex-launch", "", "declared launch JSON")
	seat := fs.String("seat", "", "seat name")
	binary := fs.String("codex", "/opt/pomar-codex/bin/codex", "pinned guest executable")
	workspace := fs.String("workspace", "/work", "guest workspace")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if !seatName.MatchString(*seat) || fs.NArg() != 0 {
		return errors.New("Codex supervisor needs a valid seat")
	}
	launch, err := parseCodexLaunch(*launchRaw)
	if err != nil {
		return err
	}
	return (codexseat.Supervisor{Launch: launch, Seat: *seat, Binary: *binary, Home: seatHome + "/.codex", StateDir: codexStateDir, Workspace: *workspace, Env: codexSeatEnv(), In: os.Stdin, Out: os.Stdout}).Run()
}

func parseCodexLaunch(raw string) (*agentenv.SeatLaunch, error) {
	if len(raw) > 4096 {
		return nil, errors.New("launch declaration too large")
	}
	var l agentenv.SeatLaunch
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&l); err != nil {
		return nil, errors.New("invalid launch declaration")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing launch declaration")
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return &l, nil
}
