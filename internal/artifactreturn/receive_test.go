package artifactreturn

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func fixture(t *testing.T) (map[string]any, Expected, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	policy := Policy{PerFileBytes: 8, MaxFiles: 4, TransferSeconds: 1, Names: []string{"release.tar", "manifest.json"}, Provisional: true}
	want := Expected{Mirror: "app", Ref: "main", SourceGit: true, Attempt: "build-1", Class: "app-linux-build", SourceSHA: strings.Repeat("a", 40), ImageDigest: "sha256:" + strings.Repeat("b", 64), CommandSHA256: strings.Repeat("c", 64), KeyID: digest(public), CallerUID: 503, PolicySHA256: PolicyDigest(policy, 16), PackageSet: strings.Repeat("d", 64), RootfsSHA256: strings.Repeat("e", 64)}
	result := map[string]any{"mirror": want.Mirror, "ref": want.Ref, "git": true, "schema": "pomar.result/v1", "attempt": want.Attempt, "class": map[string]any{"name": want.Class, "output_cap_bytes": int64(16), "artifact_output": policy}, "sha": want.SourceSHA, "image_digest": want.ImageDigest, "package_set": want.PackageSet, "rootfs_sha256": want.RootfsSHA256, "command_sha256": want.CommandSHA256, "host": want.KeyID, "started_by_uid": want.CallerUID, "state": "exited", "exit_code": 0, "artifact_output_count": 2, "outputs": []Output{{"release.tar", "ok", 3, digest([]byte("tar"))}, {"manifest.json", "ok", 2, digest([]byte("{}"))}}}
	return result, want, public, private
}
func signed(t *testing.T, result any, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := json.Marshal(map[string]any{"result": json.RawMessage(raw), "key_id": digest(key.Public().(ed25519.PublicKey)), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))})
	if err != nil {
		t.Fatal(err)
	}
	return reply
}
func root(t *testing.T) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}
func enough(*os.Root) (int64, error) { return MaxAggregateBytes, nil }
func fetchBytes(files map[string]string) Fetch {
	return func(ctx context.Context, name string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(files[name])), nil
	}
}

func TestReceiveCompleteAndNoReplay(t *testing.T) {
	doc, want, pub, priv := fixture(t)
	reply := signed(t, doc, priv)
	parent := root(t)
	files := map[string]string{"release.tar": "tar", "manifest.json": "{}"}
	ready, err := Receive(context.Background(), parent, reply, pub, want, fetchBytes(files), enough)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := parent.OpenRoot(ready)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	for name, expected := range files {
		data, err := stage.ReadFile(name)
		if err != nil || string(data) != expected {
			t.Fatalf("%s: %q %v", name, data, err)
		}
		info, _ := stage.Stat(name)
		if info.Mode().Perm() != 0400 {
			t.Fatalf("unsafe mode %v", info.Mode())
		}
	}
	receipt, err := stage.ReadFile("READY.json")
	if err != nil || !bytes.Contains(receipt, []byte(`"count":2`)) {
		t.Fatalf("receipt %s %v", receipt, err)
	}
	if _, err := Receive(context.Background(), parent, reply, pub, want, fetchBytes(files), enough); err == nil {
		t.Fatal("replayed accepted attempt")
	}
}
func TestSignedBindingsAndLimits(t *testing.T) {
	cases := map[string]func(map[string]any, *Expected){
		"source":         func(d map[string]any, w *Expected) { w.SourceSHA = strings.Repeat("f", 40) },
		"image":          func(d map[string]any, w *Expected) { w.ImageDigest = "sha256:" + strings.Repeat("f", 64) },
		"derived-layer":  func(d map[string]any, w *Expected) { w.PackageSet = strings.Repeat("f", 64) },
		"rootfs":         func(d map[string]any, w *Expected) { w.RootfsSHA256 = strings.Repeat("f", 64) },
		"command":        func(d map[string]any, w *Expected) { w.CommandSHA256 = strings.Repeat("f", 64) },
		"class":          func(d map[string]any, w *Expected) { w.Class = "wrong" },
		"caller":         func(d map[string]any, w *Expected) { w.CallerUID = 504 },
		"attempt":        func(d map[string]any, w *Expected) { w.Attempt = "other" },
		"cap":            func(d map[string]any, w *Expected) { d["class"].(map[string]any)["output_cap_bytes"] = 15 },
		"count":          func(d map[string]any, w *Expected) { d["artifact_output_count"] = 1 },
		"missing":        func(d map[string]any, w *Expected) { d["outputs"] = d["outputs"].([]Output)[:1] },
		"duplicate-name": func(d map[string]any, w *Expected) { o := d["outputs"].([]Output); o[1] = o[0] },
		"per-file":       func(d map[string]any, w *Expected) { o := d["outputs"].([]Output); o[0].Bytes = 9 },
		"not-ok":         func(d map[string]any, w *Expected) { o := d["outputs"].([]Output); o[0].Status = "missing" },
		"failed":         func(d map[string]any, w *Expected) { d["exit_code"] = 1 },
		"host-failure":   func(d map[string]any, w *Expected) { d["host_condition"] = "failed" },
		"unmeasured-raise": func(d map[string]any, w *Expected) {
			c := d["class"].(map[string]any)
			p := c["artifact_output"].(Policy)
			p.PerFileBytes = 9
			c["artifact_output"] = p
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			doc, want, pub, priv := fixture(t)
			change(doc, &want)
			if _, err := Verify(signed(t, doc, priv), pub, want); err == nil {
				t.Fatal("accepted changed binding")
			}
		})
	}
}
func TestRejectAmbiguousOrUnauthenticatedMetadata(t *testing.T) {
	doc, want, pub, priv := fixture(t)
	good := signed(t, doc, priv)
	for name, reply := range map[string][]byte{"trailing": append(append([]byte(nil), good...), []byte(" {}")...), "duplicate": bytes.Replace(good, []byte(`"result":`), []byte(`"RESULT":{},"result":`), 1), "signature": bytes.Replace(good, []byte(`"signature":"`), []byte(`"signature":"A`), 1), "oversize": bytes.Repeat([]byte(" "), MaxResultBytes+1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(reply, pub, want); err == nil {
				t.Fatal("accepted invalid metadata")
			}
		})
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
	if _, err := Verify(good, other, want); err == nil {
		t.Fatal("accepted wrong independent key")
	}
}
func TestStreamFailureFencesEntireAttempt(t *testing.T) {
	for name, files := range map[string]map[string]string{"overrun": {"release.tar": "tarEXTRA", "manifest.json": "{}"}, "truncated": {"release.tar": "ta", "manifest.json": "{}"}, "digest": {"release.tar": "bad", "manifest.json": "{}"}, "second-output": {"release.tar": "tar", "manifest.json": "x"}} {
		t.Run(name, func(t *testing.T) {
			doc, want, pub, priv := fixture(t)
			parent := root(t)
			calls := 0
			fetch := fetchBytes(files)
			path, err := Receive(context.Background(), parent, signed(t, doc, priv), pub, want, func(c context.Context, n string) (io.ReadCloser, error) { calls++; return fetch(c, n) }, enough)
			if err == nil || path != "" {
				t.Fatalf("accepted partial: %s %v", path, err)
			}
			stage, err := parent.OpenRoot(".partial-" + want.Attempt)
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Close()
			if _, err := stage.Stat("FAILED.json"); err != nil {
				t.Fatal("unfenced failure", err)
			}
			if _, err := stage.Stat("READY.json"); !os.IsNotExist(err) {
				t.Fatal("failure exposed ready marker")
			}
			if name == "overrun" {
				info, _ := stage.Stat("release.tar")
				if info.Size() > 3 {
					t.Fatal("overrun written")
				}
			}
			before := calls
			if _, err := Receive(context.Background(), parent, signed(t, doc, priv), pub, want, fetch, enough); err == nil {
				t.Fatal("replayed failure")
			}
			if calls != before {
				t.Fatal("fetched on replay")
			}
		})
	}
}
func TestSpaceAndCancellationBeforeFetch(t *testing.T) {
	for _, name := range []string{"low-space", "space-error", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			doc, want, pub, priv := fixture(t)
			parent := root(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			space := enough
			if name == "cancelled" {
				cancel()
			}
			if name == "low-space" {
				space = func(*os.Root) (int64, error) { return 15, nil }
			}
			if name == "space-error" {
				space = func(*os.Root) (int64, error) { return 0, errors.New("I/O failure") }
			}
			path, err := Receive(ctx, parent, signed(t, doc, priv), pub, want, func(context.Context, string) (io.ReadCloser, error) {
				t.Fatal("fetch before prerequisites")
				return nil, nil
			}, space)
			if err == nil || path != "" {
				t.Fatal("accepted failed preflight")
			}
		})
	}
}
func TestDeadlineClosesBlockedStream(t *testing.T) {
	doc, want, pub, priv := fixture(t)
	parent := root(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	started := time.Now()
	ready, err := Receive(context.Background(), parent, signed(t, doc, priv), pub, want, func(context.Context, string) (io.ReadCloser, error) { return pr, nil }, enough)
	if err == nil || ready != "" || time.Since(started) > 3*time.Second {
		t.Fatal("unbounded or accepted timed out transfer", err)
	}
}
func TestPolicyNamesAndMeasuredSizing(t *testing.T) {
	for _, name := range []string{"../x", "/x", "a..b", "READY.json", "original-result.json", "failed.JSON"} {
		p := Policy{8, 1, 1, []string{name}, true, 0, 0, "", ""}
		if p.Validate(16) == nil {
			t.Errorf("accepted %q", name)
		}
	}
	p := Policy{PerFileBytes: 8, MaxFiles: 2, TransferSeconds: 1, Names: []string{"Foo", "foo"}, Provisional: true}
	if p.Validate(16) == nil {
		t.Fatal("case alias")
	}
	p.Names = []string{"release.tar"}
	p.Provisional = false
	p.MeasuredBytes = 10
	p.MarginBytes = 6
	p.MeasurementAttempt = "original-1"
	p.MeasurementResultSHA = strings.Repeat("a", 64)
	if err := p.Validate(16); err != nil {
		t.Fatal(err)
	}
	p.MarginBytes = 5
	if p.Validate(16) == nil {
		t.Fatal("unstated sizing margin")
	}
}

func TestExclusiveLeafRefusesSubstitution(t *testing.T) {
	doc, want, pub, priv := fixture(t)
	parent := root(t)
	fetch := func(context.Context, string) (io.ReadCloser, error) {
		// Simulate a substituted leaf after staging creation. O_EXCL must reject
		// it, regardless of whether its target could be opened inside this root.
		if err := parent.Symlink("ORIGINAL-RESULT.json", ".partial-"+want.Attempt+"/release.tar"); err != nil {
			t.Fatal(err)
		}
		return io.NopCloser(strings.NewReader("tar")), nil
	}
	ready, err := Receive(context.Background(), parent, signed(t, doc, priv), pub, want, fetch, enough)
	if err == nil || ready != "" {
		t.Fatal("accepted substituted leaf")
	}
	raw, err := parent.ReadFile(".partial-" + want.Attempt + "/ORIGINAL-RESULT.json")
	if err != nil || !bytes.Equal(raw, signed(t, doc, priv)) {
		t.Fatal("original evidence overwritten", err)
	}
}

func TestConcurrentSameAttemptOnlyOneFetches(t *testing.T) {
	doc, want, pub, priv := fixture(t)
	parent := root(t)
	reply := signed(t, doc, priv)
	entered := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		_, err := Receive(context.Background(), parent, reply, pub, want, func(ctx context.Context, n string) (io.ReadCloser, error) {
			if n == "release.tar" {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return fetchBytes(map[string]string{"release.tar": "tar", "manifest.json": "{}"})(ctx, n)
		}, enough)
		first <- err
	}()
	<-entered
	_, err := Receive(context.Background(), parent, reply, pub, want, func(context.Context, string) (io.ReadCloser, error) {
		t.Error("duplicate attempt fetched bytes")
		return nil, errors.New("duplicate")
	}, enough)
	close(release)
	if err == nil {
		t.Fatal("concurrent replay accepted")
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}
