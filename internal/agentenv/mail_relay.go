package agentenv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const mailRequestLimit = 64 << 10
const mailResponseLimit = 1 << 20

// mailRelay is bound by the owner to one guest incarnation. It is not a
// general proxy. A dedicated local channel and Revoke on stop/replacement
// are required before this component can be integrated into a host.
type mailRelay struct {
	seat, incarnation string
	upstream          *url.URL
	client            *http.Client
	mu                sync.Mutex
	revoked           bool
	inflight          map[*http.Request]context.CancelFunc
}

var mailID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

// upstream comes from the mail service owner's API contract, never a guest.
// transport is an owner/test dependency; nil uses direct HTTP, without an
// environment-selected proxy. No credential or guest header is inherited.
func newMailRelay(seat, incarnation, upstream string, transport http.RoundTripper) (*mailRelay, error) {
	u, err := url.Parse(upstream)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return nil, errors.New("mail relay needs a fixed owner upstream")
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || host == "" || strings.ToLower(host) != host || !strings.Contains(host, ".") || strings.ContainsAny(host, "/*:@ ") || net.ParseIP(host) != nil || !seatProfileName.MatchString(seat) || !validID.MatchString(incarnation) || u.Path == "" || u.Path[0] != '/' || path.Clean(u.Path) != u.Path || strings.ContainsAny(u.Path, "%?#:") || strings.HasPrefix(u.Path, "//") {
		return nil, errors.New("mail relay needs an owner-bound seat, incarnation and API prefix")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	if transport == nil {
		transport = &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, MaxIdleConnsPerHost: 4, ResponseHeaderTimeout: 5 * time.Second}
	}
	return &mailRelay{seat: seat, incarnation: incarnation, upstream: u, inflight: map[*http.Request]context.CancelFunc{}, client: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (m *mailRelay) Revoke() {
	m.mu.Lock()
	m.revoked = true
	for _, cancel := range m.inflight {
		cancel()
	}
	m.mu.Unlock()
	m.client.CloseIdleConnections()
}

func mailRoute(r *http.Request) bool {
	if r.URL.IsAbs() || r.URL.User != nil || r.URL.Fragment != "" || strings.Contains(r.URL.EscapedPath(), "%") || path.Clean(r.URL.Path) != r.URL.Path || strings.HasPrefix(r.URL.Path, "//") {
		return false
	}
	p := r.URL.Path
	allowed := r.Method == "GET" && (p == "/whoami" || p == "/inbox" || p == "/pending") || r.Method == "POST" && p == "/send"
	for _, route := range []struct{ method, prefix string }{{"GET", "/messages/"}, {"POST", "/reply/"}} {
		if r.Method == route.method && strings.HasPrefix(p, route.prefix) && mailID.MatchString(strings.TrimPrefix(p, route.prefix)) {
			allowed = true
		}
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !allowed {
		return false
	}
	for key, values := range q {
		if p != "/inbox" || key != "limit" || len(values) != 1 {
			return false
		}
		n, err := strconv.Atoi(values[0])
		if err != nil || n < 1 || n > 200 || strconv.Itoa(n) != values[0] {
			return false
		}
	}
	return true
}

func (m *mailRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	identities := r.Header.Values("X-Zmail-Instance")
	if !mailRoute(r) || len(identities) > 1 || len(identities) == 1 && identities[0] != m.seat || r.Header.Get("Upgrade") != "" || len(r.TransferEncoding) != 0 || r.ContentLength < 0 || r.ContentLength > mailRequestLimit || r.Method == "GET" && r.ContentLength != 0 {
		http.Error(w, "mail relay refused", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	m.mu.Lock()
	if m.revoked || len(m.inflight) >= 4 {
		m.mu.Unlock()
		http.Error(w, "mail relay unavailable", http.StatusServiceUnavailable)
		return
	}
	m.inflight[r] = cancel
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.inflight, r); m.mu.Unlock() }()
	var body []byte
	if r.Method == "POST" {
		// Bound a slow local caller as well as the upstream. A transport
		// without read-deadline support is not an admitted relay channel.
		if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			http.Error(w, "mail channel unavailable", http.StatusServiceUnavailable)
			return
		}
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, mailRequestLimit+1))
		var object map[string]json.RawMessage
		if err != nil || len(body) > mailRequestLimit || json.Unmarshal(body, &object) != nil || object == nil {
			http.Error(w, "mail body refused", http.StatusBadRequest)
			return
		}
		// Identity is exclusively the owner binding. Never allow a body
		// field to acquire meaning as a future upstream identity selector.
		for key := range object {
			switch strings.ToLower(key) {
			case "seat", "instance", "from", "sender", "x-zmail-instance":
				http.Error(w, "mail identity refused", http.StatusForbidden)
				return
			}
		}
		if r.URL.Path == "/send" {
			var id string
			if json.Unmarshal(object["request_id"], &id) != nil || !mailID.MatchString(id) {
				http.Error(w, "mail request_id required", http.StatusBadRequest)
				return
			}
		}
	}
	u := *m.upstream
	u.Path += r.URL.Path
	u.RawQuery = r.URL.RawQuery
	out, err := http.NewRequestWithContext(ctx, r.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "mail request refused", http.StatusBadRequest)
		return
	}
	out.Header.Set("X-Zmail-Instance", m.seat)
	if r.Method == "POST" {
		out.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(out)
	if err != nil {
		http.Error(w, "mail upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, mailResponseLimit+1))
	m.mu.Lock()
	revoked := m.revoked
	m.mu.Unlock()
	if err != nil || len(b) > mailResponseLimit || resp.StatusCode >= 300 && resp.StatusCode < 400 || revoked {
		http.Error(w, "mail upstream refused", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(b)
}
