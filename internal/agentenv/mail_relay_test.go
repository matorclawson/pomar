package agentenv

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type mailTransport func(*http.Request) (*http.Response, error)

func (f mailTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mailResponse(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestMailRelayFixesIdentityAndUpstream(t *testing.T) {
	var calls atomic.Int32
	m, err := newMailRelay("rasa-bench", "incarnation-1", "/owner-api", mailTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Host != "messenger.zeo.ac:7743" || r.URL.Scheme != "http" || r.URL.Path != "/owner-api/send" {
			t.Errorf("unexpected upstream: %s", r.URL)
		}
		if r.Header.Get("X-Zmail-Instance") != "rasa-bench" || len(r.Header.Values("X-Zmail-Instance")) != 1 {
			t.Errorf("unbound identity: %v", r.Header)
		}
		for _, key := range []string{"Cookie", "Authorization", "Forwarded", "X-Forwarded-For"} {
			if r.Header.Get(key) != "" {
				t.Errorf("guest header forwarded: %s", key)
			}
		}
		return mailResponse(200, `{"seat":"rasa-bench"}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(m)
	defer s.Close()
	r, _ := http.NewRequest("POST", s.URL+"/send", strings.NewReader(`{"request_id":"one-send","to":"recipient","body":"hello"}`))
	r.Header.Set("X-Zmail-Instance", "rasa-bench")
	for _, key := range []string{"Cookie", "Authorization", "Forwarded", "X-Forwarded-For"} {
		r.Header.Set(key, "guest-controlled")
	}
	resp, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || calls.Load() != 1 {
		t.Fatalf("positive relay: status=%d calls=%d", resp.StatusCode, calls.Load())
	}
}

func TestMailRelayRefusesOtherSeatAndUnlistedOperations(t *testing.T) {
	for _, c := range []struct{ method, path, identity, body string }{
		{"GET", "/whoami", "architect", ""},
		{"GET", "/seats", "", ""},
		{"GET", "/export", "", ""},
		{"GET", "/watch", "", ""},
		{"POST", "/send-group", "", `{}`},
		{"POST", "/ack/id", "", `{}`},
		{"DELETE", "/messages/id", "", ""},
		{"CONNECT", "/whoami", "", ""},
		{"GET", "/messages/a/b", "", ""},
		{"GET", "/messages/%2e%2e", "", ""},
		{"GET", "/inbox?seat=architect", "", ""},
		{"GET", "/inbox?limit=1&limit=2", "", ""},
		{"GET", "/inbox?limit=201", "", ""},
		{"POST", "/send", "", `{"request_id":"id","sender":"architect"}`},
		{"POST", "/send", "", `{"body":"no request id"}`},
		{"POST", "/reply/id", "", `{"instance":"architect"}`},
	} {
		t.Run(c.method+c.path+c.identity+c.body, func(t *testing.T) {
			m, _ := newMailRelay("rasa-bench", "incarnation-1", "/owner-api", mailTransport(func(*http.Request) (*http.Response, error) {
				t.Error("refused guest request reached upstream")
				return mailResponse(200, `{}`), nil
			}))
			s := httptest.NewServer(m)
			defer s.Close()
			r, _ := http.NewRequest(c.method, s.URL+c.path, strings.NewReader(c.body))
			if c.identity != "" {
				r.Header.Set("X-Zmail-Instance", c.identity)
			}
			resp, err := s.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode < 400 {
				t.Fatalf("unlisted request accepted: %d", resp.StatusCode)
			}
		})
	}
}

func TestMailRelayDoesNotFollowRedirectOrForwardOversizeBody(t *testing.T) {
	for _, code := range []int{302, 200} {
		var calls atomic.Int32
		m, _ := newMailRelay("rasa-bench", "incarnation-1", "/owner-api", mailTransport(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			r := mailResponse(code, strings.Repeat("x", mailResponseLimit+1))
			r.Header.Set("Location", "http://other.example/steal")
			r.Header.Set("Set-Cookie", "secret=value")
			return r, nil
		}))
		w := httptest.NewRecorder()
		m.ServeHTTP(w, httptest.NewRequest("GET", "/whoami", nil))
		if calls.Load() != 1 || w.Code != 502 || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
			t.Fatalf("unsafe response escaped: code=%d calls=%d headers=%v", w.Code, calls.Load(), w.Header())
		}
	}
}

func TestMailRelayRevokesInflightAndFutureRequests(t *testing.T) {
	entered := make(chan struct{})
	m, _ := newMailRelay("rasa-bench", "incarnation-1", "/owner-api", mailTransport(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/whoami", nil))
	}()
	<-entered
	m.Revoke()
	<-done
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest("GET", "/whoami", nil))
	if w.Code != 503 {
		t.Fatalf("revoked relay accepted another request: %d", w.Code)
	}
}
