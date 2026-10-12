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
	"strings"
	"sync"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/localclient"
	"github.com/zeroemployeeorg/pomar/internal/seatterm"
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
		case seatterm.Notice:
			if notice != nil {
				notice(string(payload))
			}
		}
	}
}
