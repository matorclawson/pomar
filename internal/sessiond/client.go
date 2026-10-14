package sessiond

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/localclient"
	"github.com/zeroemployeeorg/pomar/internal/seatterm"
	"github.com/zeroemployeeorg/pomar/internal/termstate"
)

// ErrNoService is a root with no service answering on its socket.
var ErrNoService = errors.New("no session service is running for this root")

// Client calls a session service over its socket, checking the socket's
// custody and the kernel's peer uid before anything is sent.
type Client struct {
	Root string
	http *http.Client
}

// NewClient returns a client for the service serving root.
func NewClient(root string) *Client {
	root = canonical(root)
	c := localclient.New(filepath.Join(root, SocketName), os.Geteuid())
	c.Timeout = 30 * time.Second
	return &Client{Root: root, http: c}
}

// Refusal is a refusal from the service, with its kind.
type Refusal struct {
	Status int
	APIError
}

func (r *Refusal) Error() string { return r.APIError.Error }

// Do sends a JSON request and decodes the reply into out. A reply that
// never came is ErrNoReply's: the request's effect is unknown, and is
// looked up by its operation ID, never resent under a new one.
func (c *Client) Do(method, path string, body, out any) error {
	if _, err := os.Lstat(filepath.Join(c.Root, SocketName)); err != nil {
		return ErrNoService
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://sessions"+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "connection failed") || strings.Contains(err.Error(), "custody") || strings.Contains(err.Error(), "refused") {
			return fmt.Errorf("%w: %v", ErrNoService, err)
		}
		return fmt.Errorf("%w: %v", ErrNoReply, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoReply, err)
	}
	if resp.StatusCode >= 300 {
		r := &Refusal{Status: resp.StatusCode}
		if json.Unmarshal(b, &r.APIError) != nil || r.Kind == "" {
			// a send or stop that did something reports its outcome, not a refusal
			var res opResult
			if json.Unmarshal(b, &res) == nil && res.Outcome != "" {
				r.Kind, r.APIError.Error = KindUncertain, res.Outcome+": "+res.Detail
			} else {
				r.Kind, r.APIError.Error = KindInternal, resp.Status
			}
		}
		return r
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// ErrNoReply is a request whose reply never came: its effect is unknown.
var ErrNoReply = errors.New("the session service didn't reply; the request's effect is unknown")

// LogChunk is one bounded read of a session's durable log.
type LogChunk struct {
	Data      []byte
	Size      int64 // the log's whole size, as of this read
	From      int64 // this chunk's offset into the log
	Truncated bool  // more of the log follows this chunk
}

// RawGet sends a GET and returns its raw body, never JSON-decoded, for a
// log's bytes.
func (c *Client) RawGet(path string) (LogChunk, error) {
	if _, err := os.Lstat(filepath.Join(c.Root, SocketName)); err != nil {
		return LogChunk{}, ErrNoService
	}
	req, err := http.NewRequest("GET", "http://sessions"+path, nil)
	if err != nil {
		return LogChunk{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "connection failed") || strings.Contains(err.Error(), "custody") || strings.Contains(err.Error(), "refused") {
			return LogChunk{}, fmt.Errorf("%w: %v", ErrNoService, err)
		}
		return LogChunk{}, fmt.Errorf("%w: %v", ErrNoReply, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxLogChunk+4<<10))
	if err != nil {
		return LogChunk{}, fmt.Errorf("%w: %v", ErrNoReply, err)
	}
	if resp.StatusCode >= 300 {
		r := &Refusal{Status: resp.StatusCode}
		if json.Unmarshal(b, &r.APIError) != nil || r.Kind == "" {
			r.Kind, r.APIError.Error = KindInternal, resp.Status
		}
		return LogChunk{}, r
	}
	chunk := LogChunk{Data: b}
	chunk.Size, _ = strconv.ParseInt(resp.Header.Get("X-Pomar-Log-Size"), 10, 64)
	chunk.From, _ = strconv.ParseInt(resp.Header.Get("X-Pomar-Log-From"), 10, 64)
	chunk.Truncated, _ = strconv.ParseBool(resp.Header.Get("X-Pomar-Log-Truncated"))
	return chunk, nil
}

// OpResult is a send's or stop's reply.
type OpResult = opResult

// DetachKey is the key a client takes as its detach, never sending it: Ctrl-].
const DetachKey = 0x1d

// Attach opens a session's terminal: view keeps it read-only, and take
// takes control from whoever holds it.
func (c *Client) Attach(name string, view, take bool) (io.ReadWriteCloser, error) {
	conn, err := localclient.Dial(context.Background(), filepath.Join(c.Root, SocketName), os.Geteuid())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoService, err)
	}
	q := url.Values{}
	if view {
		q.Set("view", "1")
	}
	if take {
		q.Set("take", "1")
	}
	target := "/v1/sessions/" + url.PathEscape(name) + "/attach?" + q.Encode()
	if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: sessions\r\nConnection: Upgrade\r\nUpgrade: %s\r\nContent-Length: 0\r\n\r\n", target, seatterm.ProtocolV2); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		r := &Refusal{Status: resp.StatusCode}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		if json.Unmarshal(b, &r.APIError) != nil || r.Kind == "" {
			r.Kind, r.APIError.Error = KindInternal, resp.Status
		}
		conn.Close()
		return nil, r
	}
	return &stream{ReadWriteCloser: conn, r: br}, nil
}

type stream struct {
	io.ReadWriteCloser
	r *bufio.Reader
}

func (s *stream) Read(p []byte) (int, error) { return s.r.Read(p) }

// Pump carries a local terminal over an attach stream: the window size
// first, then input, each size change, and the session's screen to out,
// until the session ends, the stream drops, or the detach key is typed.
// The detach key is never sent. Notices are handed to notice as they come.
// It reports whether the client detached by its key.
func Pump(st io.ReadWriteCloser, in io.Reader, out io.Writer, cols, rows uint16, resizes <-chan [2]uint16, notice func(string)) (bool, error) {
	return PumpWith(st, in, out, cols, rows, resizes, Hooks{Notice: notice})
}

// Hooks are what a pump hands its caller beside the screen: notices, the
// session's presence and agent state, and control answers and changes,
// each as it comes. Requests carries the caller's control requests (op
// request, take or release) to the session. Any of them may be nil.
type Hooks struct {
	Notice   func(string)
	Presence func(seatterm.PresenceMsg)
	State    func(seatterm.AgentState)
	Control  func(seatterm.ControlMsg)
	Requests <-chan seatterm.ControlMsg
	// Safe, when set, is called after each write to out with whether out
	// now stands between sequences and characters, where the caller may
	// write its own (a window title) without splitting the program's.
	Safe func(bool)
}

// PumpWith is Pump with every hook.
func PumpWith(st io.ReadWriteCloser, in io.Reader, out io.Writer, cols, rows uint16, resizes <-chan [2]uint16, h Hooks) (bool, error) {
	var wmu sync.Mutex
	sendFrame := func(kind byte, b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return seatterm.WriteFrame(st, kind, b)
	}
	if err := sendFrame(seatterm.Resize, seatterm.ResizePayload(cols, rows)); err != nil {
		return false, err
	}
	detached := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := in.Read(buf)
			if i := bytes.IndexByte(buf[:n], DetachKey); i >= 0 {
				if i > 0 {
					sendFrame(seatterm.Data, buf[:i])
				}
				sendFrame(seatterm.Close, nil)
				close(detached)
				st.Close()
				return
			}
			if n > 0 && sendFrame(seatterm.Data, buf[:n]) != nil {
				return
			}
			if err != nil {
				sendFrame(seatterm.Close, nil)
				return
			}
		}
	}()
	if resizes != nil {
		go func() {
			for size := range resizes {
				if size[0] >= 1 && size[0] <= seatterm.MaxCols && size[1] >= 1 && size[1] <= seatterm.MaxRows {
					if sendFrame(seatterm.Resize, seatterm.ResizePayload(size[0], size[1])) != nil {
						return
					}
				}
			}
		}()
	}
	if h.Requests != nil {
		go func() {
			for {
				select {
				case m, ok := <-h.Requests:
					if !ok {
						return
					}
					b, _ := json.Marshal(seatterm.ControlMsg{Op: m.Op})
					if sendFrame(seatterm.Control, b) != nil {
						return
					}
				case <-stop:
					return
				}
			}
		}()
	}
	// model only follows the output's parser state, for Safe.
	var model *termstate.Terminal
	if h.Safe != nil {
		model = termstate.New(int(cols), int(rows), 0)
	}
	for {
		kind, payload, err := seatterm.ReadFrameV2(st)
		select {
		case <-detached:
			return true, nil
		default:
		}
		if err == io.EOF || kind == seatterm.Close {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		switch kind {
		case seatterm.Data:
			if _, err := out.Write(payload); err != nil {
				return false, err
			}
			if model != nil {
				model.Feed(payload)
				model.Replies()
				n, ok := model.Held()
				h.Safe(ok && n == 0)
			}
		case seatterm.Notice:
			if h.Notice != nil {
				h.Notice(string(payload))
			}
		case seatterm.Presence:
			var m seatterm.PresenceMsg
			if h.Presence != nil && json.Unmarshal(payload, &m) == nil {
				h.Presence(m)
			}
		case seatterm.State:
			var m seatterm.AgentState
			if h.State != nil && json.Unmarshal(payload, &m) == nil {
				h.State(m)
			}
		case seatterm.Control:
			var m seatterm.ControlMsg
			if h.Control != nil && json.Unmarshal(payload, &m) == nil {
				h.Control(m)
			}
		}
	}
}
