// Package seatmigration prepares explicit tmux-to-Pomar adoption plans.
// Discovery is not fencing, history import, or permission to launch an actor.
package seatmigration

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const Format = "#{session_id}\t#{window_id}\t#{pane_id}\t#{pane_pid}\t#{pane_dead}\t#{session_name}\t#{pane_current_command}\t#{pane_current_path}"
const MaxInventory = 4 << 20

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var tmuxID = regexp.MustCompile(`^[%@$][0-9]+$`)

type Pane struct {
	SessionID   string `json:"session_id"`
	WindowID    string `json:"window_id"`
	PaneID      string `json:"pane_id"`
	PanePID     int    `json:"pane_pid"`
	Dead        bool   `json:"dead"`
	SessionName string `json:"session_name"`
	Command     string `json:"command"`
	CWD         string `json:"cwd"`
}
type Inventory struct {
	Schema string `json:"schema"`
	Socket string `json:"socket"`
	Panes  []Pane `json:"panes"`
}
type Assignment struct {
	Seat               string `json:"seat"`
	PaneID             string `json:"pane_id"`
	SessionID          string `json:"session_id"`
	Environment        string `json:"environment"`
	Profile            string `json:"profile"`
	Harness            string `json:"harness"`
	NativeConversation string `json:"native_conversation"`
	MemoryBytes        int64  `json:"memory_bytes"`
	CPUMillis          int64  `json:"cpu_millis"`
}
type Manifest struct {
	Schema          string       `json:"schema"`
	InventorySHA256 string       `json:"inventory_sha256"`
	MemoryBudget    int64        `json:"memory_budget_bytes"`
	CPUBudget       int64        `json:"cpu_budget_millis"`
	Seats           []Assignment `json:"seats"`
}
type SeatPlan struct {
	Assignment Assignment `json:"assignment"`
	Source     Pane       `json:"source"`
	Blockers   []string   `json:"blockers"`
}
type Plan struct {
	Schema          string     `json:"schema"`
	InventorySHA256 string     `json:"inventory_sha256"`
	CanCutOver      bool       `json:"can_cut_over"`
	Seats           []SeatPlan `json:"seats"`
	Unmapped        []string   `json:"unmapped_panes"`
	MemoryRequired  int64      `json:"memory_required_bytes"`
	CPURequired     int64      `json:"cpu_required_millis"`
	AllFit          bool       `json:"all_fit"`
	Stages          []string   `json:"stages"`
}

func Parse(socket string, data []byte) (Inventory, error) {
	inv := Inventory{Schema: "pomar.tmux-inventory/v1", Socket: socket, Panes: []Pane{}}
	if !filepath.IsAbs(socket) || len(data) > MaxInventory {
		return inv, errors.New("explicit socket and bounded inventory required")
	}
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 4096), 65536)
	seen := map[string]bool{}
	for scan.Scan() {
		f := strings.Split(scan.Text(), "\t")
		if len(f) != 8 {
			return inv, errors.New("ambiguous tmux fields; refusing partial inventory")
		}
		pid, e := strconv.Atoi(f[3])
		if e != nil || pid < 1 || !tmuxID.MatchString(f[0]) || f[0][0] != '$' || !tmuxID.MatchString(f[1]) || f[1][0] != '@' || !tmuxID.MatchString(f[2]) || f[2][0] != '%' || seen[f[2]] || (f[4] != "0" && f[4] != "1") || !filepath.IsAbs(f[7]) {
			return inv, errors.New("invalid or duplicate tmux pane")
		}
		seen[f[2]] = true
		inv.Panes = append(inv.Panes, Pane{f[0], f[1], f[2], pid, f[4] == "1", f[5], f[6], f[7]})
		if len(inv.Panes) > 1024 {
			return inv, errors.New("inventory pane limit")
		}
	}
	return inv, scan.Err()
}
func Digest(inv Inventory) string {
	b, _ := json.Marshal(inv)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func Build(inv Inventory, m Manifest) (Plan, error) {
	p := Plan{Schema: "pomar.seat-migration-plan/v1", InventorySHA256: Digest(inv), Seats: []SeatPlan{}, Unmapped: []string{}, Stages: []string{"inventory-and-explicit-identity-mapping", "capture-final-workspace-and-native-history-after-source-fence", "prepare-stopped-box-with-scoped-credentials", "verify-exact-native-resume-and-terminal", "switch-runtime-location-with-original-operation-id", "retain-fenced-source-for-rollback"}}
	if inv.Schema != "pomar.tmux-inventory/v1" || m.Schema != "pomar.seat-migration/v1" || m.InventorySHA256 != p.InventorySHA256 || m.MemoryBudget < 1 || m.MemoryBudget > 4<<40 || m.CPUBudget < 1 || m.CPUBudget > 1024000 || len(m.Seats) == 0 || len(m.Seats) > 1024 {
		return p, errors.New("invalid manifest, capacity, or stale inventory binding")
	}
	panes := map[string]Pane{}
	for _, v := range inv.Panes {
		if panes[v.PaneID].PaneID != "" {
			return p, errors.New("duplicate inventory pane")
		}
		panes[v.PaneID] = v
	}
	used, envs, seats := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range m.Seats {
		src, ok := panes[a.PaneID]
		if !ok || src.SessionID != a.SessionID || used[a.PaneID] || envs[a.Environment] || seats[a.Seat] || len(a.NativeConversation) > 256 || strings.ContainsAny(a.NativeConversation, "\r\n\t") || a.Seat == "" || len(a.Seat) > 256 || strings.ContainsAny(a.Seat, "\r\n\t") || !identifier.MatchString(a.Environment) || !identifier.MatchString(a.Profile) || (a.Harness != "claude" && a.Harness != "codex") || a.MemoryBytes < 256<<20 || a.MemoryBytes > 1<<40 || a.CPUMillis < 1 || a.CPUMillis > 256000 {
			return p, errors.New("invalid, duplicated or stale seat assignment")
		}
		used[a.PaneID] = true
		envs[a.Environment] = true
		seats[a.Seat] = true
		p.MemoryRequired += a.MemoryBytes
		p.CPURequired += a.CPUMillis
		blockers := []string{"native-history importer and exact resume qualification required", "source actor and descendants must be fenced before activation", "Runtime location handoff and credential enrollment required"}
		if src.Dead {
			blockers = append(blockers, "source pane is dead; reconcile its last actor outcome")
		}
		if a.NativeConversation == "" {
			blockers = append(blockers, "exact native conversation identity missing")
		}
		if src.CWD != "/work" {
			blockers = append(blockers, "source workspace path differs from guest /work; qualify history/path relocation")
		}
		p.Seats = append(p.Seats, SeatPlan{a, src, blockers})
	}
	for _, v := range inv.Panes {
		if !used[v.PaneID] {
			p.Unmapped = append(p.Unmapped, v.PaneID)
		}
	}
	p.AllFit = p.MemoryRequired <= m.MemoryBudget && p.CPURequired <= m.CPUBudget
	return p, nil
}
