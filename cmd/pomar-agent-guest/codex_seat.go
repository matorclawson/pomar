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
	"syscall"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/agentenv"
	"github.com/zeroemployeeorg/pomar/internal/codexseat"
	"github.com/zeroemployeeorg/pomar/internal/seatterm"
)

func codexSeatEnv() []string {
	return []string{"HOME=" + seatHome, "CODEX_HOME=" + seatHome + "/.codex", "PATH=/opt/pomar-codex/codex-path:/pomar/job/.local/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin", "TERM=xterm-256color", "LANG=C.UTF-8", "HTTPS_PROXY=http://127.0.0.1:7072", "HTTP_PROXY=http://127.0.0.1:7072", "ALL_PROXY=http://127.0.0.1:7072", "GOPROXY=http://127.0.0.1:7070", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly"}
}

func codexTmuxEnsure(seat, binary, self, workspace string, launch *agentenv.SeatLaunch) []string {
	data, _ := json.Marshal(launch)
	return []string{seatTmux, "-S", seatTmuxSocket, "new-session", "-d", "-s", seatSession, "-x", "200", "-y", "50", "--", self, "codex-seat-supervisor", "-seat", seat, "-codex", binary, "-workspace", workspace, "-codex-launch", string(data)}
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
	if err = os.MkdirAll(seatTmuxDir, 0700); err != nil {
		return err
	}
	if err = os.Chown(seatTmuxDir, seatUID, seatGID); err != nil {
		return err
	}
	command := func(argv []string) *exec.Cmd {
		c := exec.Command(argv[0], argv[1:]...)
		c.Env = codexSeatEnv()
		c.Dir = seatHome
		c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: seatUID, Gid: seatGID}}
		return c
	}
	ensure := func() error {
		if command(tmuxHas()).Run() == nil {
			return nil
		}
		if err := command(codexTmuxEnsure(seat, binary, self, workspace, launch)).Run(); err != nil {
			return errors.New("Codex seat supervisor did not start; inspect guest custody")
		}
		return nil
	}
	attach := tmuxAttach()
	attach.Env = codexSeatEnv()
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
		s := codexseat.Supervisor{Seat: seat, Binary: binary, Home: seatHome + "/.codex", StateDir: seatStateDir + "/codex", Workspace: workspace, Launch: launch, Env: codexSeatEnv()}
		info, e := s.InspectStartup()
		if e != nil {
			http.Error(w, "startup inspection held", 409)
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
		launchRecord := codexseat.Supervisor{Seat: seat, Binary: binary, Home: seatHome + "/.codex", StateDir: seatStateDir + "/codex", Workspace: workspace, Launch: launch, Env: codexSeatEnv()}
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
	return (codexseat.Supervisor{Launch: launch, Seat: *seat, Binary: *binary, Home: seatHome + "/.codex", StateDir: seatStateDir + "/codex", Workspace: *workspace, Env: codexSeatEnv(), In: os.Stdin, Out: os.Stdout}).Run()
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
