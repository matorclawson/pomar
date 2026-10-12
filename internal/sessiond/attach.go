package sessiond

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/seatterm"
)

// attach upgrades to seatterm.ProtocolV2 and carries one client of a
// session: the client's window size first; then the session's presence and
// agent state, its exact screen, and its live output, with notices and meta
// frames beside it. A controlling client's input and size changes reach the
// program; a viewer's never do. A client asks for control, takes it or
// releases it with Control frames, and is told each change to its role.
// A dropped connection is a detach, and never stops the program.
func (s *Server) attach(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), seatterm.ProtocolV2) || !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		refuse(w, http.StatusBadRequest, KindUsage, "attach is an upgrade to "+seatterm.ProtocolV2)
		return
	}
	t := s.lookup(w, r)
	if t == nil {
		return
	}
	q := r.URL.Query()
	view, take := q.Get("view") == "1", q.Get("take") == "1"
	p := principalOf(r)
	c, _, err := t.Attach(p)
	if err != nil {
		hostError(w, err)
		return
	}
	defer c.Detach()
	hj, ok := w.(http.Hijacker)
	if !ok {
		refuse(w, http.StatusInternalServerError, KindInternal, "the connection can't be upgraded")
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + seatterm.ProtocolV2 + "\r\nConnection: Upgrade\r\n\r\n")); err != nil {
		return
	}
	in := bufio.NewReader(&readThrough{Conn: conn, r: buf.Reader})
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, size, err := seatterm.ReadFrame(in)
	if err != nil || kind != seatterm.Resize {
		seatterm.WriteFrame(conn, seatterm.Close, nil)
		return
	}
	conn.SetReadDeadline(time.Time{})
	cols, rows := binary.BigEndian.Uint16(size), binary.BigEndian.Uint16(size[2:])

	var wmu sync.Mutex
	send := func(kind byte, b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		for {
			n := min(len(b), seatterm.MaxData)
			if err := seatterm.WriteFrame(conn, kind, b[:n]); err != nil {
				return err
			}
			if b = b[n:]; len(b) == 0 {
				return nil
			}
		}
	}
	meta := func(kind byte, v any) error {
		wmu.Lock()
		defer wmu.Unlock()
		return seatterm.WriteMeta(conn, kind, v)
	}
	notice := func(format string, a ...any) {
		m := fmt.Sprintf(format, a...)
		if len(m) > seatterm.MaxNotice {
			m = m[:seatterm.MaxNotice]
		}
		send(seatterm.Notice, []byte(m))
	}
	// Presence and agent state are sent on attach and when they change.
	var lastPresence string
	var lastSeq uint64
	presence := func() error {
		b, _ := json.Marshal(c.Presence())
		if string(b) == lastPresence {
			return nil
		}
		lastPresence = string(b)
		wmu.Lock()
		defer wmu.Unlock()
		return seatterm.WriteFrame(conn, seatterm.Presence, b)
	}
	agent := func(force bool) error {
		st, _ := t.Agent()
		if !force && st.Seq == lastSeq {
			return nil
		}
		lastSeq = st.Seq
		return meta(seatterm.State, st)
	}

	controls := false
	if !view {
		if epoch, err := c.Control(take, "attach"); err == nil {
			controls = true
			meta(seatterm.Control, seatterm.ControlMsg{Event: "granted", Epoch: epoch})
			// The session takes the controller's size; the screen is cut
			// once that is applied, so it is drawn at the size the client has.
			if in := t.Info(); in.Cols != cols || in.Rows != rows {
				if c.Resize(cols, rows) == nil {
					for end := time.Now().Add(time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
						if in := t.Info(); in.Cols == cols && in.Rows == rows {
							break
						}
					}
				}
			}
		} else {
			meta(seatterm.Control, seatterm.ControlMsg{Event: "refused", Epoch: t.Info().Epoch, Reason: err.Error()})
			notice("viewing: another client controls %s; attach with -take to take control", t.Name)
		}
	}
	screen := func(snap seatterm.Snapshot) error {
		if !snap.ScreenExact {
			defer notice("the screen may not be exact: it was cut inside a sequence the model can't hold")
		}
		if snap.Cols != cols || snap.Rows != rows {
			defer notice("the session is %dx%d, and your terminal %dx%d", snap.Cols, snap.Rows, cols, rows)
		}
		return send(seatterm.Data, snap.Screen)
	}
	if presence() != nil || agent(true) != nil || screen(c.Resnapshot()) != nil {
		return
	}
	if !controls {
		notice("viewing %s: your input isn't sent", t.Name)
	}

	// released is set while this client gives control up itself, so the
	// change isn't reported as taken.
	var released atomic.Bool
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		warned := false
		for {
			kind, payload, err := seatterm.ReadFrameV2(in)
			if err != nil || kind == seatterm.Close {
				return
			}
			switch kind {
			case seatterm.Control:
				var m seatterm.ControlMsg
				json.Unmarshal(payload, &m)
				switch m.Op {
				case "request", "take":
					if epoch, err := c.Control(m.Op == "take", "attach "+m.Op); err != nil {
						meta(seatterm.Control, seatterm.ControlMsg{Event: "refused", Epoch: t.Info().Epoch, Reason: err.Error()})
					} else {
						meta(seatterm.Control, seatterm.ControlMsg{Event: "granted", Epoch: epoch})
					}
				case "release":
					if c.Controls() {
						released.Store(true)
						c.Release()
					}
					meta(seatterm.Control, seatterm.ControlMsg{Event: "released", Epoch: t.Info().Epoch})
				default:
					meta(seatterm.Control, seatterm.ControlMsg{Event: "refused", Reason: "unknown control op"})
				}
				warned = false
			case seatterm.Data, seatterm.Resize:
				if !c.Controls() {
					if !warned {
						notice("viewing: your input isn't sent")
						warned = true
					}
					continue
				}
				if kind == seatterm.Data {
					if err := c.Input(payload); err != nil {
						notice("input refused: %v", err)
					}
				} else {
					c.Resize(binary.BigEndian.Uint16(payload), binary.BigEndian.Uint16(payload[2:]))
				}
			default:
				// the host's own frames: a client never sends them, and they act on nothing
			}
		}
	}()
	held := controls
	for {
		select {
		case <-gone:
			return
		case e, ok := <-c.Events():
			if !ok {
				if in := t.Info(); !in.Running && in.ExitCode != nil {
					notice("%s exited with code %d", t.Name, *in.ExitCode)
				}
				presence()
				agent(false)
				send(seatterm.Close, nil)
				return
			}
			if send(seatterm.Data, e.Data) != nil {
				return
			}
		case <-c.Signals():
			if behind, _ := c.Gap(); behind {
				if screen(c.Resnapshot()) != nil {
					return
				}
				notice("you fell behind; the screen was redrawn")
			}
			if now := c.Controls(); now != held {
				held = now
				if now {
					notice("you control %s", t.Name)
				} else if !released.Swap(false) && t.Info().Running { // an exit ends control too, and is said by its own notice
					meta(seatterm.Control, seatterm.ControlMsg{Event: "taken", Epoch: t.Info().Epoch})
					notice("control of %s was taken; you're viewing", t.Name)
				}
			}
			if presence() != nil || agent(false) != nil {
				return
			}
		}
	}
}

// readThrough reads through the bytes the HTTP server buffered past the
// request.
type readThrough struct {
	net.Conn
	r *bufio.Reader
}

func (c *readThrough) Read(p []byte) (int, error) { return c.r.Read(p) }
