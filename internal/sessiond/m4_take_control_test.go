package sessiond

import (
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/seatterm"
)

// council M4: an attached operator must never be locked out of a session
// he's attached to. This proves the end-to-end path a held Ctrl-^ drives
// (cmd/pomar's takeKeyReader is unit-tested separately for the byte-level
// part): a dispossessed controller asks for control back over the same
// Requests channel sessionAttach wires to that key, and gets it, without
// detaching and reattaching with -take.
func TestADispossessedControllerTakesControlBackWithoutDetaching(t *testing.T) {
	_, c := serve(t, root(t))
	req := shell("op-1", "work", `printf 'ready\n'; while read l; do printf 'got:%s\n' "$l"; done`)
	if err := c.Do("POST", "/v1/sessions", req, nil); err != nil {
		t.Fatal(err)
	}
	waitScreen(t, c, "work", "ready")

	// The operator attaches first and controls the session.
	ops, err := c.Attach("work", false, false)
	if err != nil {
		t.Fatal(err)
	}
	opIn, opInW := io.Pipe()
	opOut := &lockedBuffer{}
	var opEvents []seatterm.ControlMsg
	var opMu sync.Mutex
	opReq := make(chan seatterm.ControlMsg, 1)
	opDone := make(chan bool, 1)
	go func() {
		d, _ := PumpWith(ops, opIn, opOut, 60, 8, nil, Hooks{
			Requests: opReq,
			Control: func(m seatterm.ControlMsg) {
				opMu.Lock()
				opEvents = append(opEvents, m)
				opMu.Unlock()
			},
		})
		opDone <- d
	}()

	// Automation attaches with take: the operator is dispossessed.
	autoSt, err := c.Attach("work", false, true)
	if err != nil {
		t.Fatal(err)
	}
	autoIn, autoInW := io.Pipe()
	go PumpWith(autoSt, autoIn, io.Discard, 60, 8, nil, Hooks{})

	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		opMu.Lock()
		taken := len(opEvents) > 0 && opEvents[len(opEvents)-1].Event == "taken"
		opMu.Unlock()
		if taken {
			break
		}
	}
	opMu.Lock()
	if len(opEvents) == 0 || opEvents[len(opEvents)-1].Event != "taken" {
		t.Fatalf("the dispossessed operator was never told control was taken: %+v", opEvents)
	}
	opMu.Unlock()

	// The operator's typing no longer reaches the program.
	opInW.Write([]byte("ignored\r"))
	time.Sleep(100 * time.Millisecond)

	// Ctrl-^, in cmd/pomar, turns into exactly this: a take request on the
	// channel sessionAttach wires to the operator's own Pump.
	opReq <- seatterm.ControlMsg{Op: "take"}

	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		opMu.Lock()
		granted := len(opEvents) > 0 && opEvents[len(opEvents)-1].Event == "granted"
		opMu.Unlock()
		if granted {
			break
		}
	}
	opMu.Lock()
	if len(opEvents) == 0 || opEvents[len(opEvents)-1].Event != "granted" {
		t.Fatalf("the operator's take-back was never granted: %+v", opEvents)
	}
	opMu.Unlock()

	// Control is back: the operator's typing reaches the program again,
	// and automation (now a viewer) can't send any more.
	opInW.Write([]byte("back\r"))
	waitScreen(t, c, "work", "got:back")
	autoInW.Write([]byte("blocked\r"))
	time.Sleep(200 * time.Millisecond)
	scr := screenOf(t, c, "work")
	if strings.Contains(strings.Join(scr.Lines, "\n"), "got:blocked") {
		t.Fatal("dispossessed automation's input still reached the program")
	}
	if strings.Contains(strings.Join(scr.Lines, "\n"), "got:ignored") {
		t.Fatal("the operator's input reached the program while dispossessed")
	}
}
