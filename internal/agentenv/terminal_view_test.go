package agentenv

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// This fake exercises the required atomic-consume interface, NOT real durable
// storage/restart custody. That implementation and native acceptance stay owed.
type viewReplayFake struct {
	mu    sync.Mutex
	used  map[string]bool
	fail  bool
	delay time.Duration
	calls int
}

func (r *viewReplayFake) Consume(_ context.Context, iss, aud, jti string, _ time.Time) (bool, error) {
	time.Sleep(r.delay)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.fail {
		return false, errors.New("unavailable")
	}
	k := iss + "\x00" + aud + "\x00" + jti
	if r.used[k] {
		return false, nil
	}
	r.used[k] = true
	return true, nil
}

type viewFixture struct {
	p      *TerminalViewPolicy
	priv   ed25519.PrivateKey
	claims map[string]any
	b      TerminalViewBinding
	now    time.Time
	r      *viewReplayFake
}

func newViewFixture(t *testing.T) *viewFixture {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	p, e := NewTerminalViewPolicy(TerminalViewConfig{Issuer: "connect", Audience: "host1", Org: "org1", Application: "app1", Profile: "terminal1", HostNamespace: "namespace1", Keys: map[string]ed25519.PublicKey{"key1": pub}})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	iat := now.Unix()
	return &viewFixture{p: p, priv: priv, now: now, b: TerminalViewBinding{Environment: "env1", Seat: "seat1", Session: "session1", Incarnation: "inc1", Host: "host1", Profile: "terminal1", HostNamespace: "namespace1", AuthorityEpoch: 1, BindingRev: 1, FreshUntil: now.Add(60 * time.Second)}, r: &viewReplayFake{used: make(map[string]bool)}, claims: map[string]any{"iss": "connect", "aud": "host1", "sub": "person1", "hiss": "session-issuer", "org": "org1", "app": "app1", "gid": "grant1", "seat": "seat1", "env": "env1", "mode": "read", "iat": iat, "nbf": iat, "exp": iat + 120, "jti": "opening1"}}
}
func (f *viewFixture) signRaw(header, payload string) string {
	a := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	return a + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.priv, []byte(a)))
}
func (f *viewFixture) token() string {
	b, _ := json.Marshal(f.claims)
	return f.signRaw(`{"alg":"EdDSA","kid":"key1","typ":"zeoconnect-terminal-grant+jwt"}`, string(b))
}
func (f *viewFixture) open(t *testing.T) *TerminalViewLease {
	t.Helper()
	l, e := f.p.Open(context.Background(), f.token(), f.b.Environment, f.now, f.b, f.r)
	if e != nil {
		t.Fatal(e)
	}
	return l
}

func TestTerminalViewValidGrantAndHardLeaseCaps(t *testing.T) {
	for _, mode := range []string{"lease", "grant", "runtime"} {
		t.Run(mode, func(t *testing.T) {
			f := newViewFixture(t)
			want := f.now.Add(30 * time.Second)
			if mode == "grant" {
				f.claims["exp"] = f.now.Unix() + 5
				want = time.Unix(f.now.Unix()+5, 0)
			}
			if mode == "runtime" {
				f.b.FreshUntil = f.now.Add(3 * time.Second)
				want = f.b.FreshUntil
			}
			l := f.open(t)
			if !l.Deadline().Equal(want) {
				t.Fatalf("deadline=%v want=%v", l.Deadline(), want)
			}
		})
	}
}
func TestTerminalViewRejectsInvalidClaimsBeforeReplay(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "foreign" }}, {"wrong audience", func(c map[string]any) { c["aud"] = "host2" }},
		{"audience list", func(c map[string]any) { c["aud"] = []string{"host1"} }}, {"wrong org", func(c map[string]any) { c["org"] = "other" }},
		{"wrong app", func(c map[string]any) { c["app"] = "other" }}, {"control mode", func(c map[string]any) { c["mode"] = "control" }},
		{"wrong seat", func(c map[string]any) { c["seat"] = "seat2" }}, {"wrong environment", func(c map[string]any) { c["env"] = "env2" }},
		{"missing", func(c map[string]any) { delete(c, "hiss") }}, {"unknown", func(c map[string]any) { c["socket"] = "/unsafe" }},
		{"null subject", func(c map[string]any) { c["sub"] = nil }}, {"control character", func(c map[string]any) { c["sub"] = "person\n1" }},
		{"expired despite skew", func(c map[string]any) { c["exp"] = time.Now().Unix() }},
		{"overlong lifetime", func(c map[string]any) { c["exp"] = c["iat"].(int64) + 121 }},
		{"different nbf", func(c map[string]any) { c["nbf"] = c["iat"].(int64) - 1 }},
		{"future", func(c map[string]any) {
			c["iat"] = time.Now().Unix() + 31
			c["nbf"] = c["iat"]
			c["exp"] = c["iat"].(int64) + 30
		}},
		{"float", func(c map[string]any) { c["exp"] = 1.5 }}, {"oversize", func(c map[string]any) { c["sub"] = strings.Repeat("x", 2049) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newViewFixture(t)
			test.change(f.claims)
			_, e := f.p.Open(context.Background(), f.token(), f.b.Environment, f.now, f.b, f.r)
			if e != ErrTerminalViewRefused || f.r.calls != 0 {
				t.Fatalf("error=%v replaycalls=%d", e, f.r.calls)
			}
		})
	}
}
func TestTerminalViewRejectsDuplicateHeaderClaimAndKeySubstitution(t *testing.T) {
	for _, mode := range []string{"duplicate claim", "duplicate header", "unknown header", "unknown kid", "algorithm", "wrong typ", "bad signature", "padding", "trailing payload"} {
		t.Run(mode, func(t *testing.T) {
			f := newViewFixture(t)
			payload, _ := json.Marshal(f.claims)
			h := `{"alg":"EdDSA","kid":"key1","typ":"zeoconnect-terminal-grant+jwt"}`
			body := string(payload)
			switch mode {
			case "duplicate claim":
				body = strings.TrimSuffix(body, "}") + `,"seat":"seat1"}`
			case "duplicate header":
				h = strings.TrimSuffix(h, "}") + `,"kid":"key1"}`
			case "unknown header":
				h = strings.TrimSuffix(h, "}") + `,"jku":"https://untrusted"}`
			case "unknown kid":
				h = strings.Replace(h, "key1", "other", 1)
			case "algorithm":
				h = strings.Replace(h, "EdDSA", "HS256", 1)
			case "wrong typ":
				h = strings.Replace(h, "zeoconnect-terminal-grant+jwt", "delegation+jwt", 1)
			case "trailing payload":
				body += " {}"
			}
			token := f.signRaw(h, body)
			if mode == "bad signature" {
				parts := strings.Split(token, ".")
				parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
				token = strings.Join(parts, ".")
			}
			if mode == "padding" {
				token += "="
			}
			if _, e := f.p.Open(context.Background(), token, f.b.Environment, f.now, f.b, f.r); e != ErrTerminalViewRefused || f.r.calls != 0 {
				t.Fatal(mode, e, f.r.calls)
			}
		})
	}
}
func TestTerminalViewRejectsUntrustedBindings(t *testing.T) {
	for _, mode := range []string{"environment", "session", "host", "profile", "namespace", "epoch", "revision", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newViewFixture(t)
			switch mode {
			case "environment":
				f.b.Environment = ""
			case "session":
				f.b.Session = ""
			case "host":
				f.b.Host = "other"
			case "profile":
				f.b.Profile = "other"
			case "namespace":
				f.b.HostNamespace = "other"
			case "epoch":
				f.b.AuthorityEpoch = 0
			case "revision":
				f.b.BindingRev = 0
			case "expired":
				f.b.FreshUntil = f.now
			}
			if _, e := f.p.Open(context.Background(), f.token(), f.b.Environment, f.now, f.b, f.r); e != ErrTerminalViewRefused || f.r.calls != 0 {
				t.Fatal(mode, e)
			}
		})
	}
}
func TestTerminalViewOpeningIsSingleUseAndUnknownRefuses(t *testing.T) {
	f := newViewFixture(t)
	token := f.token()
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := f.p.Open(context.Background(), token, f.b.Environment, f.now, f.b, f.r); e == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("multiple admitted views", success)
	}
	// A fresh policy object cannot bypass the SAME required replay-store custody.
	again, _ := NewTerminalViewPolicy(f.p.config)
	if _, e := again.Open(context.Background(), token, f.b.Environment, f.now, f.b, f.r); e != ErrTerminalViewRefused {
		t.Fatal("replay accepted", e)
	}
	f = newViewFixture(t)
	f.r.fail = true
	if _, e := f.p.Open(context.Background(), f.token(), f.b.Environment, f.now, f.b, f.r); e != ErrTerminalViewRefused {
		t.Fatal(e)
	}
	if _, e := f.p.Open(context.Background(), f.token(), f.b.Environment, f.now, f.b, nil); e != ErrTerminalViewRefused {
		t.Fatal(e)
	}
}
func TestTerminalViewLateAdmissionCannotStartExpiredLease(t *testing.T) {
	f := newViewFixture(t)
	f.b.FreshUntil = f.now.Add(time.Millisecond)
	f.r.delay = 5 * time.Millisecond
	if _, e := f.p.Open(context.Background(), f.token(), f.b.Environment, f.now, f.b, f.r); e != ErrTerminalViewRefused {
		t.Fatal("late store completion admitted", e)
	}
}
func TestTerminalViewRenewalNeverExtendsOriginalGrantOrResurrects(t *testing.T) {
	f := newViewFixture(t)
	f.claims["exp"] = f.now.Unix() + 40
	l := f.open(t)
	yes := true
	now := f.now.Add(20 * time.Second)
	fresh := f.b
	fresh.FreshUntil = now.Add(time.Minute)
	fresh.BindingRev++
	if !l.Renew(now, fresh, &yes) || !l.Deadline().Equal(time.Unix(f.now.Unix()+40, 0)) {
		t.Fatal("grant cap changed", l.Deadline())
	}
	if l.Renew(l.Deadline(), fresh, &yes) || l.Renew(now, fresh, &yes) {
		t.Fatal("expired lease reopened")
	}
}
func TestTerminalViewUnknownRenewalDoesNotExtendAndRevocationCloses(t *testing.T) {
	f := newViewFixture(t)
	l := f.open(t)
	first := l.Deadline()
	if !l.Renew(f.now.Add(time.Second), f.b, nil) || !l.Deadline().Equal(first) {
		t.Fatal("unknown check extended")
	}
	no := false
	yes := true
	if l.Renew(f.now.Add(2*time.Second), f.b, &no) || l.Renew(f.now.Add(3*time.Second), f.b, &yes) {
		t.Fatal("revoked lease reopened")
	}
}
func TestTerminalViewIdentityChangesAndAuthorityRollbackClose(t *testing.T) {
	for _, mode := range []string{"environment", "seat", "session", "incarnation", "host", "profile", "namespace", "epoch", "revision", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newViewFixture(t)
			f.b.BindingRev = 2
			l := f.open(t)
			changed := f.b
			switch mode {
			case "environment":
				changed.Environment = "other"
			case "seat":
				changed.Seat = "other"
			case "session":
				changed.Session = "other"
			case "incarnation":
				changed.Incarnation = "other"
			case "host":
				changed.Host = "other"
			case "profile":
				changed.Profile = "other"
			case "namespace":
				changed.HostNamespace = "other"
			case "epoch":
				changed.AuthorityEpoch++
			case "revision":
				changed.BindingRev--
			case "expired":
				changed.FreshUntil = f.now
			}
			if l.Observe(f.now.Add(time.Millisecond), changed) || l.Observe(f.now.Add(2*time.Millisecond), f.b) {
				t.Fatal("changed identity retained/reopened")
			}
		})
	}
}
func TestTerminalViewOnlyClosesFromClientAndBoundsServerFrames(t *testing.T) {
	for i := 0; i < 256; i++ {
		for _, size := range []int{-1, 0, 1, 100, 32769} {
			want := byte(i) == 'x' && size == 0
			if TerminalViewClientFrameAllowed(byte(i), size) != want {
				t.Fatal(i, size)
			}
		}
	}
	for _, test := range []struct {
		k    byte
		n    int
		want bool
	}{{'d', 32768, true}, {'d', 32769, false}, {'n', 512, true}, {'n', 513, false}, {'x', 0, true}, {'x', 1, false}, {'c', 0, false}, {'r', 4, false}, {'d', -1, false}} {
		if TerminalViewServerFrameAllowed(test.k, test.n) != test.want {
			t.Fatal(test)
		}
	}
}
func TestTerminalViewConfigurationKeysAreSnapshotCopied(t *testing.T) {
	f := newViewFixture(t)
	key := f.p.config.Keys["key1"]
	config := f.p.config
	config.Keys = map[string]ed25519.PublicKey{"key1": append(ed25519.PublicKey(nil), key...)}
	p, e := NewTerminalViewPolicy(config)
	if e != nil {
		t.Fatal(e)
	}
	config.Keys["key1"][0] ^= 0xff
	delete(config.Keys, "key1")
	if _, e := p.Open(context.Background(), f.token(), f.b.Environment, f.now, f.b, f.r); e != nil {
		t.Fatal("caller mutated policy keys", e)
	}
}

func TestTerminalViewV3RouteAndGrantEnvironmentAreBound(t *testing.T) {
	f := newViewFixture(t)
	if _, e := f.p.Open(context.Background(), f.token(), "foreign-route", f.now, f.b, f.r); e != ErrTerminalViewRefused || f.r.calls != 0 {
		t.Fatal("foreign route admitted", e)
	}
	// A v2 signed-inc grant is not accepted as an optional v3 alternative.
	delete(f.claims, "env")
	f.claims["inc"] = "inc1"
	if _, e := f.p.Open(context.Background(), f.token(), f.b.Environment, f.now, f.b, f.r); e != ErrTerminalViewRefused || f.r.calls != 0 {
		t.Fatal("legacy grant accepted", e)
	}
}
func TestTerminalViewV3PinsResolvedIncarnationWithoutGrantInc(t *testing.T) {
	f := newViewFixture(t)
	f.b.Incarnation = "actual-current-incarnation"
	l := f.open(t)
	changed := f.b
	changed.Incarnation = "next-incarnation"
	if l.Observe(f.now.Add(time.Millisecond), changed) {
		t.Fatal("view retargeted across incarnation")
	}
	// The original single-use grant cannot silently open the new actor either.
	if _, e := f.p.Open(context.Background(), f.token(), f.b.Environment, f.now, changed, f.r); e != ErrTerminalViewRefused {
		t.Fatal("consumed grant retargeted", e)
	}
}
