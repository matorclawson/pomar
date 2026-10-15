package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const healthCapacityFixture = `{"host":{"cpu_slots":8,"memory_bytes":21474836480},"space":{"used":100,"avail":200},"live":1,"draining":false,"coverage":"KNOWN_NONTERMINAL_ATTEMPTS_ONLY","current":[{"name":"ci-example","allocation":{"fits_current":0,"failures":[{"resource":"CPU_BUDGET","deficit":2000,"unit":"millicores","demand":4000,"available":2000}]}}]}`

func healthServer(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	d, err := os.MkdirTemp(os.TempDir(), "ph-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	s := filepath.Join(d, "ctl.sock")
	l, err := net.Listen("unix", s)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return s
}

func healthKeyFixture() (string, string) {
	b := bytes.Repeat([]byte{7}, 32)
	hash := sha256.Sum256(b)
	id := hex.EncodeToString(hash[:])
	j, _ := json.Marshal(map[string]string{"algorithm": "ed25519", "public_key": base64.StdEncoding.EncodeToString(b), "key_id": id})
	return string(j), id
}

func TestHealthUsesOnlyAuthorizedReadRoutesAndReportsDeficits(t *testing.T) {
	key, id := healthKeyFixture()
	var mu sync.Mutex
	requests := []string{}
	s := healthServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/v1/capacity":
			w.Write([]byte(healthCapacityFixture))
		case "/v1/signing-key":
			w.Write([]byte(key))
		default:
			w.WriteHeader(500)
		}
	})
	var out, errs bytes.Buffer
	if rc := run([]string{"health", "-json", "-socket", s, "-expected-key-id", id}, &out, &errs); rc != 0 {
		t.Fatalf("rc%d %s", rc, errs.String())
	}
	var r healthReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Manager.Status != "RESPONSIVE" || r.ResultKey.Status != "MATCH" || r.Admission.Status != "NO_NUMERIC_FIT" || len(r.Classes) != 1 || r.Classes[0].Failures[0].Deficit != 2000 || len(r.Unknown) < 6 || r.Evidence != "UNSIGNED_MANAGER_OBSERVATIONS" {
		t.Fatal(r)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(requests, ",") != "GET /v1/capacity,GET /v1/signing-key" {
		t.Fatal(requests)
	}
	if !strings.Contains(r.ResultKey.Detail, "not proof") {
		t.Fatal("public bytes were treated as execution proof")
	}
}

func TestHealthLegacyIdleFitIsNeverCurrentRoom(t *testing.T) {
	key, _ := healthKeyFixture()
	s := healthServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/signing-key" {
			w.Write([]byte(key))
			return
		}
		w.Write([]byte(`{"host":{"cpu_slots":8,"memory_bytes":20},"space":{"used":10,"avail":20},"live":7,"draining":false,"fits_idle":4}`))
	})
	var out, errs bytes.Buffer
	if rc := run([]string{"health", "-json", "-socket", s}, &out, &errs); rc != 0 {
		t.Fatal(rc)
	}
	var r healthReport
	json.Unmarshal(out.Bytes(), &r)
	if r.Admission.Status != "UNKNOWN" || len(r.Classes) != 0 || r.ResultKey.Status != "UNPINNED" {
		t.Fatal(r)
	}
	if r.Coverage != "LEGACY_CURRENT_CLAIMS_UNAVAILABLE" {
		t.Fatal(r.Coverage)
	}
}

func TestHealthV1NestedKeysAreStable(t *testing.T) {
	key, id := healthKeyFixture()
	s := healthServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/signing-key" {
			w.Write([]byte(key))
			return
		}
		w.Write([]byte(healthCapacityFixture))
	})
	var out, errs bytes.Buffer
	if rc := run([]string{"health", "-json", "-socket", s, "-expected-key-id", id}, &out, &errs); rc != 0 {
		t.Fatalf("rc%d %s", rc, errs.String())
	}
	var report map[string]any
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	keys := func(v any, expected string) {
		t.Helper()
		obj, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("expected object, got %T", v)
		}
		actual := []string{}
		for k := range obj {
			actual = append(actual, k)
		}
		sort.Strings(actual)
		want := strings.Fields(expected)
		sort.Strings(want)
		if strings.Join(actual, " ") != strings.Join(want, " ") {
			t.Fatalf("keys %v, want %v", actual, want)
		}
	}
	keys(report, "schema observed_at evidence_kind status socket client_version client_source manager result_key_binding result_key_id admission configured_host_budget disk known_live_attempts capacity_coverage caller_visible_classes unknown next_steps")
	for _, name := range []string{"manager", "result_key_binding", "admission"} {
		keys(report[name], "status detail")
	}
	keys(report["configured_host_budget"], "cpu_slots memory_bytes")
	keys(report["disk"], "used avail device shared")
	classes, ok := report["caller_visible_classes"].([]any)
	if !ok || len(classes) != 1 {
		t.Fatal(report)
	}
	keys(classes[0], "name fits_current failures")
	class := classes[0].(map[string]any)
	failures, ok := class["failures"].([]any)
	if !ok || len(failures) != 1 {
		t.Fatal(class)
	}
	keys(failures[0], "resource reason unit demand available deficit")
}

func TestHealthDrainAndWrongKeyDoNotAuthorizeWork(t *testing.T) {
	key, _ := healthKeyFixture()
	s := healthServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/signing-key" {
			w.Write([]byte(key))
			return
		}
		w.Write([]byte(strings.Replace(healthCapacityFixture, `"draining":false`, `"draining":true`, 1)))
	})
	var out, errs bytes.Buffer
	if rc := run([]string{"health", "-json", "-socket", s, "-expected-key-id", strings.Repeat("0", 64)}, &out, &errs); rc != 1 {
		t.Fatal(rc)
	}
	var r healthReport
	json.Unmarshal(out.Bytes(), &r)
	if r.Admission.Status != "DRAINING" || r.ResultKey.Status != "MISMATCH" || r.Status != "ATTENTION" {
		t.Fatal(r)
	}
}

func TestHealthBoundsAndDeniedResponsesAreExplicit(t *testing.T) {
	for _, tc := range []struct {
		code         int
		body, status string
	}{{403, `{"error":"PRIVATE_DETAIL"}`, "HTTP_403"}, {200, `{}`, "INVALID_REPLY"}, {200, healthCapacityFixture + strings.Repeat(" ", (1<<20)+1), "INVALID_REPLY"}, {302, ``, "HTTP_302"}} {
		t.Run(tc.status, func(t *testing.T) {
			s := healthServer(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.code == 302 {
					w.Header().Set("Location", "http://elsewhere/private")
				}
				w.WriteHeader(tc.code)
				w.Write([]byte(tc.body))
			})
			var out, errs bytes.Buffer
			if rc := run([]string{"health", "-json", "-socket", s}, &out, &errs); rc != 1 {
				t.Fatal(rc)
			}
			var r healthReport
			json.Unmarshal(out.Bytes(), &r)
			if r.Manager.Status != tc.status || r.Admission.Status != "UNKNOWN" || strings.Contains(out.String(), "PRIVATE_DETAIL") {
				t.Fatal(out.String())
			}
		})
	}
}

func TestHealthTotalDeadlineAndExplicitTarget(t *testing.T) {
	s := healthServer(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	var out, errs bytes.Buffer
	start := time.Now()
	if rc := run([]string{"health", "-json", "-socket", s, "-timeout", "100ms"}, &out, &errs); rc != 1 {
		t.Fatal(rc)
	}
	if time.Since(start) > time.Second {
		t.Fatal("total deadline was not bounded")
	}
	t.Setenv("POMAR_SOCKET", "")
	out.Reset()
	errs.Reset()
	if rc := run([]string{"health", "-json"}, &out, &errs); rc != 2 {
		t.Fatal(rc)
	}
	var r healthReport
	json.Unmarshal(out.Bytes(), &r)
	if r.Status != "NOT_SELECTED" || r.Live != nil || r.Host != nil {
		t.Fatal(r)
	}
	out.Reset()
	errs.Reset()
	t.Setenv("POMAR_SOCKET", s)
	if rc := run([]string{"health", "-json", "-root", "/does-not-exist"}, &out, &errs); rc != 1 {
		t.Fatal(rc)
	}
	json.Unmarshal(out.Bytes(), &r)
	if r.Socket == s {
		t.Fatal("explicit root ignored")
	}
}
