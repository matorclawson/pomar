package seatmigration

import (
	"fmt"
	"strings"
	"testing"
)

func TestInventoryRejectsAmbiguousAndDuplicatePanes(t *testing.T) {
	row := "$1\t@2\t%3\t123\t0\tmail-seat\tnode\t/work\n"
	inv, e := Parse("/explicit/tmux", []byte(row))
	if e != nil || len(inv.Panes) != 1 {
		t.Fatal(inv, e)
	}
	for _, bad := range []string{row + row, strings.Replace(row, "/work", "/a\tb", 1), strings.Replace(row, "123", "no", 1)} {
		if _, e = Parse("/explicit/tmux", []byte(bad)); e == nil {
			t.Fatal("ambiguous inventory accepted")
		}
	}
}
func TestPlanBindsIdentityAndNeverClaimsCutover(t *testing.T) {
	inv, _ := Parse("/explicit/tmux", []byte("$1\t@2\t%3\t123\t0\tmail-seat\tnode\t/old/work\n"))
	a := Assignment{Seat: "seat@example", PaneID: "%3", SessionID: "$1", Environment: "seat-one", Profile: "claude", Harness: "claude", MemoryBytes: 2 << 30, CPUMillis: 1000}
	m := Manifest{Schema: "pomar.seat-migration/v1", InventorySHA256: Digest(inv), MemoryBudget: 1 << 30, CPUBudget: 1000, Seats: []Assignment{a}}
	p, e := Build(inv, m)
	if e != nil || p.CanCutOver || p.AllFit || len(p.Seats[0].Blockers) < 4 {
		t.Fatal(p, e)
	}
	m.Seats = append(m.Seats, a)
	if _, e = Build(inv, m); e == nil {
		t.Fatal("duplicate writer planned")
	}
	m.Seats = m.Seats[:1]
	m.InventorySHA256 = strings.Repeat("0", 64)
	if _, e = Build(inv, m); e == nil {
		t.Fatal("stale inventory accepted")
	}
}
func TestFiftySeatMemoryIsNotAssumedToFit(t *testing.T) {
	inv := Inventory{Schema: "pomar.tmux-inventory/v1", Socket: "/explicit/tmux"}
	m := Manifest{Schema: "pomar.seat-migration/v1", MemoryBudget: 48 << 30, CPUBudget: 8000}
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("%d", i)
		inv.Panes = append(inv.Panes, Pane{SessionID: "$" + id, PaneID: "%" + id, CWD: "/work"})
		m.Seats = append(m.Seats, Assignment{Seat: "seat" + id, PaneID: "%" + id, SessionID: "$" + id, Environment: "seat" + id, Profile: "codex", Harness: "codex", MemoryBytes: 2 << 30, CPUMillis: 1000})
	}
	m.InventorySHA256 = Digest(inv)
	p, e := Build(inv, m)
	if e != nil || p.AllFit || p.MemoryRequired != 100<<30 || len(p.Seats) != 50 {
		t.Fatal(p, e)
	}
}
