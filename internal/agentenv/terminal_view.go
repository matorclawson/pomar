package agentenv

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

// Source-only policy for CONTRACT-v2-DRAFT c24e8428. No route, key bootstrap,
// resolver, replay journal, credential, renewal client or terminal is installed.
var ErrTerminalViewRefused = errors.New("terminal view refused")

// TerminalViewBinding must come from the owner and authenticated Runtime fact,
// never a browser. FreshUntil is a hard authority/freshness deadline. The route
// must watch local identity changes and call Observe immediately, even while an
// upstream read or downstream write is blocked. Unknown authority closes a view.
type TerminalViewBinding struct {
	Environment, Seat, Session, Incarnation, Host, Profile, HostNamespace string
	AuthorityEpoch, BindingRev                                            uint64
	FreshUntil                                                            time.Time
}

type TerminalViewConfig struct {
	Issuer, Audience, Org, Application, Profile, HostNamespace string
	Keys                                                       map[string]ed25519.PublicKey
}

type TerminalViewPolicy struct{ config TerminalViewConfig }

func NewTerminalViewPolicy(c TerminalViewConfig) (*TerminalViewPolicy, error) {
	for _, s := range []string{c.Issuer, c.Audience, c.Org, c.Application, c.Profile, c.HostNamespace} {
		if !viewWord(s) {
			return nil, ErrTerminalViewRefused
		}
	}
	keys := make(map[string]ed25519.PublicKey)
	for kid, key := range c.Keys {
		if !viewWord(kid) || len(key) != ed25519.PublicKeySize {
			return nil, ErrTerminalViewRefused
		}
		keys[kid] = append(ed25519.PublicKey(nil), key...)
	}
	if len(keys) == 0 {
		return nil, ErrTerminalViewRefused
	}
	c.Keys = keys
	return &TerminalViewPolicy{config: c}, nil
}

// Consume must atomically and durably consume (issuer,audience,jti) through exp,
// including concurrent calls and restart. false/error/unknown means refuse.
// There is deliberately no in-memory or default permissive implementation.
type TerminalViewReplay interface {
	Consume(context.Context, string, string, string, time.Time) (bool, error)
}

type viewGrant struct {
	issuer, audience, subject, hiss, org, app, gid, seat, inc, jti string
	expires                                                        time.Time
}

// TerminalViewLease is concurrency-safe policy state, not a running timer or
// transport. Its owning route must enforce Deadline/Observe at the output
// boundary, interrupt stalled I/O at expiry, and never forward client commands.
type TerminalViewLease struct {
	mu       sync.Mutex
	grant    viewGrant
	binding  TerminalViewBinding
	deadline time.Time
	closed   bool
}

// Open consumes an opening exactly once; response loss cannot authorize a retry.
// now must be an owner time.Now sample (with its monotonic component), not input
// from a grant/client. Delayed replay-store completion cannot move the deadline.
func (p *TerminalViewPolicy) Open(ctx context.Context, token string, now time.Time, b TerminalViewBinding, replay TerminalViewReplay) (*TerminalViewLease, error) {
	if p == nil || replay == nil || ctx.Err() != nil || !p.validBinding(b, now) {
		return nil, ErrTerminalViewRefused
	}
	g, err := p.verify(token, now)
	if err != nil || g.seat != b.Seat || g.inc != b.Incarnation {
		return nil, ErrTerminalViewRefused
	}
	deadline := viewDeadline(now, g.expires, b.FreshUntil)
	ok, err := replay.Consume(ctx, g.issuer, g.audience, g.jti, g.expires)
	if err != nil || !ok || ctx.Err() != nil || !time.Now().Before(deadline) {
		return nil, ErrTerminalViewRefused
	}
	return &TerminalViewLease{grant: g, binding: b, deadline: deadline}, nil
}

func (p *TerminalViewPolicy) validBinding(b TerminalViewBinding, now time.Time) bool {
	if !b.FreshUntil.After(now) || b.Host != p.config.Audience || b.Profile != p.config.Profile || b.HostNamespace != p.config.HostNamespace || b.AuthorityEpoch == 0 || b.BindingRev == 0 {
		return false
	}
	for _, s := range []string{b.Environment, b.Seat, b.Session, b.Incarnation} {
		if !viewWord(s) {
			return false
		}
	}
	return true
}

func viewWord(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, c := range s {
		if c <= 32 || c == 127 {
			return false
		}
	}
	return true
}

// strictViewObject rejects duplicate/unknown/missing fields before decoding
// values. JSON unmarshal into a struct alone silently accepts duplicate keys.
func strictViewObject(raw []byte, fields string) (map[string]json.RawMessage, error) {
	allowed := make(map[string]bool)
	for _, key := range strings.Fields(fields) {
		allowed[key] = true
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return nil, ErrTerminalViewRefused
	}
	values := make(map[string]json.RawMessage)
	for d.More() {
		t, e := d.Token()
		key, ok := t.(string)
		if e != nil || !ok || !allowed[key] || values[key] != nil {
			return nil, ErrTerminalViewRefused
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, ErrTerminalViewRefused
		}
		values[key] = v
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || len(values) != len(allowed) {
		return nil, ErrTerminalViewRefused
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrTerminalViewRefused
	}
	return values, nil
}

func viewString(m map[string]json.RawMessage, k string) string {
	var s string
	if json.Unmarshal(m[k], &s) != nil || !viewWord(s) {
		return ""
	}
	return s
}
func viewInt(m map[string]json.RawMessage, k string) (int64, bool) {
	var n int64
	if json.Unmarshal(m[k], &n) != nil || n <= 0 {
		return 0, false
	}
	return n, true
}
func viewDecode(s string) ([]byte, error) {
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, ErrTerminalViewRefused
	}
	return b, nil
}
func (p *TerminalViewPolicy) verify(token string, now time.Time) (viewGrant, error) {
	bad := func() (viewGrant, error) { return viewGrant{}, ErrTerminalViewRefused }
	if len(token) > 2048 {
		return bad()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return bad()
	}
	header, e := viewDecode(parts[0])
	if e != nil {
		return bad()
	}
	h, e := strictViewObject(header, "alg kid typ")
	if e != nil || viewString(h, "alg") != "EdDSA" || viewString(h, "typ") != "zeoconnect-terminal-grant+jwt" {
		return bad()
	}
	key := p.config.Keys[viewString(h, "kid")]
	if len(key) != ed25519.PublicKeySize {
		return bad()
	}
	sig, e := viewDecode(parts[2])
	if e != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return bad()
	}
	payload, e := viewDecode(parts[1])
	if e != nil {
		return bad()
	}
	c, e := strictViewObject(payload, "iss aud sub hiss org app gid seat inc mode iat nbf exp jti")
	if e != nil {
		return bad()
	}
	g := viewGrant{issuer: viewString(c, "iss"), audience: viewString(c, "aud"), subject: viewString(c, "sub"), hiss: viewString(c, "hiss"), org: viewString(c, "org"), app: viewString(c, "app"), gid: viewString(c, "gid"), seat: viewString(c, "seat"), inc: viewString(c, "inc"), jti: viewString(c, "jti")}
	for _, s := range []string{g.issuer, g.audience, g.subject, g.hiss, g.org, g.app, g.gid, g.seat, g.inc, g.jti} {
		if s == "" {
			return bad()
		}
	}
	if g.issuer != p.config.Issuer || g.audience != p.config.Audience || g.org != p.config.Org || g.app != p.config.Application || viewString(c, "mode") != "read" {
		return bad()
	}
	iat, ok := viewInt(c, "iat")
	nbf, nok := viewInt(c, "nbf")
	exp, eok := viewInt(c, "exp")
	if !ok || !nok || !eok || nbf != iat || exp <= iat || exp-iat > 120 || iat > now.Add(30*time.Second).Unix() {
		return bad()
	}
	g.expires = time.Unix(exp, 0)
	if !g.expires.After(now) {
		return bad()
	}
	return g, nil
}
func viewDeadline(now, grantExpiry, freshExpiry time.Time) time.Time {
	remaining := 30 * time.Second
	for _, expiry := range []time.Time{grantExpiry, freshExpiry} {
		if d := expiry.Sub(now); d < remaining {
			remaining = d
		}
	}
	return now.Add(remaining)
}
func (l *TerminalViewLease) observeLocked(now time.Time, b TerminalViewBinding) bool {
	old := l.binding
	if l.closed || !now.Before(l.deadline) || !b.FreshUntil.After(now) || b.Environment != old.Environment || b.Seat != old.Seat || b.Session != old.Session || b.Incarnation != old.Incarnation || b.Host != old.Host || b.Profile != old.Profile || b.HostNamespace != old.HostNamespace || b.AuthorityEpoch != old.AuthorityEpoch || b.BindingRev < old.BindingRev {
		l.closed = true
		return false
	}
	// A freshly shortened authority deadline shortens an existing lease too.
	if fresh := now.Add(b.FreshUntil.Sub(now)); fresh.Before(l.deadline) {
		l.deadline = fresh
	}
	l.binding = b
	return true
}
func (l *TerminalViewLease) Observe(now time.Time, b TerminalViewBinding) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.observeLocked(now, b)
}
func (l *TerminalViewLease) Deadline() time.Time { l.mu.Lock(); defer l.mu.Unlock(); return l.deadline }

// decision is nil for 503/timeout/unknown/unbound/late checks: no extension.
// Only a fresh authenticated response bound by the owner check client to this
// view's exact pending request may supply true. false closes immediately. The
// route owns request-id reuse and a single <=2s check; this policy issues no HTTP.
func (l *TerminalViewLease) Renew(now time.Time, b TerminalViewBinding, decision *bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.observeLocked(now, b) {
		return false
	}
	if decision == nil {
		return true
	}
	if !*decision {
		l.closed = true
		return false
	}
	next := viewDeadline(now, l.grant.expires, b.FreshUntil)
	if !next.After(now) {
		l.closed = true
		return false
	}
	l.deadline = next
	return true
}

// Client close detaches only this view. Even query replies, resize and explicit
// control requests are refused. The actual adapter must invoke this per frame.
func TerminalViewClientFrameAllowed(kind byte, size int) bool { return kind == 'x' && size == 0 }
func TerminalViewServerFrameAllowed(kind byte, size int) bool {
	if size < 0 {
		return false
	}
	return kind == 'd' && size <= 32768 || kind == 'n' && size <= 512 || kind == 'x' && size == 0
}
