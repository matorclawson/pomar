package postgres

// sow: pomar-SOW-87 rev27. Synthetic pins never imply installed tool authority.
import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixtureTools(t *testing.T) (string, string, Tools) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("production refuses root; use an ordinary test account")
	}
	d := t.TempDir()
	prefix := filepath.Join(d, "tools")
	if e := os.Mkdir(prefix, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(prefix, "bin"), 0700); e != nil {
		t.Fatal(e)
	}
	osRaw, e := os.ReadFile(OSIdentityPath())
	if e != nil {
		t.Fatal(e)
	}
	m := Tools{Schema: "pomar.postgres-tools/v1", Version: "17.11", Platform: runtime.GOOS + "/" + runtime.GOARCH, OSIdentitySHA256: hash(osRaw), SourceSHA256: strings.Repeat("a", 64), Prefix: prefix, Owner: uint32(os.Geteuid()), BootstrapRole: "fixture_owner"}
	for _, n := range []string{"initdb", "postgres", "psql"} {
		b := []byte("synthetic nonexecuted " + n + "\n")
		p := "bin/" + n
		if e := os.WriteFile(filepath.Join(prefix, p), b, 0700); e != nil {
			t.Fatal(e)
		}
		m.Files = append(m.Files, FilePin{Path: p, SHA256: hash(b), Bytes: int64(len(b)), Mode: 0700})
	}
	path := filepath.Join(d, "manifest.json")
	raw, _ := json.Marshal(m)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return path, hash(raw), m
}
func TestManifestRefusesMutationOmissionExtrasAndWrongPlatform(t *testing.T) {
	for _, change := range []string{"bytes", "unlisted", "missing", "platform", "manifest-digest", "duplicate-json", "symlink-parent"} {
		t.Run(change, func(t *testing.T) {
			p, h, m := fixtureTools(t)
			if _, e := VerifyTools(context.Background(), p, h); e != nil {
				t.Fatal(e)
			}
			switch change {
			case "bytes":
				if e := os.WriteFile(filepath.Join(m.Prefix, "bin/psql"), []byte("changed"), 0700); e != nil {
					t.Fatal(e)
				}
			case "unlisted":
				if e := os.WriteFile(filepath.Join(m.Prefix, "unlisted"), []byte("extra"), 0600); e != nil {
					t.Fatal(e)
				}
			case "missing":
				if e := os.Remove(filepath.Join(m.Prefix, "bin/psql")); e != nil {
					t.Fatal(e)
				}
			case "platform":
				m.Platform = "other/arch"
				b, _ := json.Marshal(m)
				if e := os.WriteFile(p, b, 0600); e != nil {
					t.Fatal(e)
				}
				h = hash(b)
			case "manifest-digest":
				h = strings.Repeat("b", 64)
			case "duplicate-json":
				b, _ := os.ReadFile(p)
				b = bytes.Replace(b, []byte(`"version":"17.11"`), []byte(`"version":"17.11","version":"17.11"`), 1)
				if e := os.WriteFile(p, b, 0600); e != nil {
					t.Fatal(e)
				}
				h = hash(b)
			case "symlink-parent":
				old := m.Prefix
				real := old + "-real"
				if e := os.Rename(old, real); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(real, old); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := VerifyTools(context.Background(), p, h); e == nil {
				t.Fatal("changed closure accepted")
			}
		})
	}
}
func TestToolLinksMustStayWithinExactClosure(t *testing.T) {
	p, _, m := fixtureTools(t)
	link := filepath.Join(m.Prefix, "psql-link")
	if e := os.Symlink("bin/psql", link); e != nil {
		t.Fatal(e)
	}
	m.Files = append(m.Files, FilePin{Path: "psql-link", Mode: 0777, Link: "bin/psql"})
	b, _ := json.Marshal(m)
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyTools(context.Background(), p, hash(b)); e != nil {
		t.Fatal("safe pinned link refused", e)
	}
	if e := os.Remove(link); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("../manifest.json", link); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyTools(context.Background(), p, hash(b)); e == nil {
		t.Fatal("changed/escaping link accepted")
	}
}
func TestEnvironmentDoesNotInheritCredentialsOrAcceptDBOverride(t *testing.T) {
	t.Setenv("DATABASE_URL", "secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("PGPASSWORD", "secret")
	env, e := environment(Config{Env: []string{"PATH=/explicit/bin", "CI=true"}}, "/private/home", "/private/socket", "reviewed_owner")
	if e != nil {
		t.Fatal(e)
	}
	s := strings.Join(env, "\n")
	for _, key := range []string{"DATABASE_URL=", "AWS_SECRET_ACCESS_KEY=", "PGPASSWORD="} {
		if strings.Contains(s, key) {
			t.Fatal("inherited credentials", key)
		}
	}
	if !strings.Contains(s, "PGHOST=/private/socket") || !strings.Contains(s, "PATH=/explicit/bin") {
		t.Fatal("missing explicit bindings")
	}
	for _, x := range []string{"PGHOST=elsewhere", "DATABASE_URL=elsewhere", "HOME=elsewhere", "PGSERVICEFILE=elsewhere"} {
		if _, e := environment(Config{Env: []string{x}}, "/h", "/s", "r"); e == nil {
			t.Fatal("unreviewed environment accepted", x)
		}
	}
}
func TestBudgetOverflowCancelsWithoutUnboundedOutput(t *testing.T) {
	f, e := os.Create(filepath.Join(t.TempDir(), "log"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &boundedLog{f: f, limit: 4, cancel: cancel}
	if n, e := l.Write([]byte("123456789")); n != 9 || e != nil {
		t.Fatal(n, e)
	}
	if ctx.Err() == nil || l.complete() {
		t.Fatal("overflow reported complete")
	}
	b, _ := os.ReadFile(f.Name())
	if string(b) != "1234" {
		t.Fatal("retention bound not enforced", string(b))
	}
}
func TestMetadataIsExclusiveAndIncompleteIntentCannotBeReused(t *testing.T) {
	d := t.TempDir()
	r, e := os.OpenRoot(d)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e := persist(r, "intent.json", map[string]string{"state": "before-effects"}); e != nil {
		t.Fatal(e)
	}
	if e := persist(r, "intent.json", map[string]string{"state": "replayed"}); e == nil {
		t.Fatal("original intent overwritten")
	}
	b, _ := os.ReadFile(filepath.Join(d, "intent.json"))
	if !bytes.Contains(b, []byte("before-effects")) {
		t.Fatal("original evidence lost")
	}
	if e := os.WriteFile(filepath.Join(d, "partial.json"), []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := persist(r, "partial.json", map[string]bool{"new": true}); e == nil {
		t.Fatal("partial intent reset")
	}
}
func TestMissingExtensionRefusesBeforeAnyClusterEffect(t *testing.T) {
	p, h, _ := fixtureTools(t)
	d := t.TempDir()
	c := Config{WorkRoot: d, GateDir: d, Manifest: p, ManifestSHA256: h, Gate: []string{"/usr/bin/true"}, Extensions: map[string]string{"pg_graphql": "1.6.1"}, Whole: time.Minute, Startup: time.Second, Stop: time.Second, LogBytes: 4096}
	r, e := Run(context.Background(), c)
	if e == nil || r.Root != "" {
		t.Fatal("missing extension created invocation", r, e)
	}
	ls, _ := os.ReadDir(d)
	if len(ls) != 0 {
		t.Fatal("refusal changed work root")
	}
}

func TestShutdownDeadlineRetainsUncertainCustodyAndNeverSucceeds(t *testing.T) {
	p, _, m := fixtureTools(t)
	scripts := map[string]string{"initdb": "#!/bin/sh\nexit 0\n", "psql": "#!/bin/sh\nprintf 't\\n'\n", "postgres": "#!/bin/sh\ntrap '' INT\nwhile :; do :; done\n"}
	for i, pin := range m.Files {
		b := []byte(scripts[filepath.Base(pin.Path)])
		if e := os.WriteFile(filepath.Join(m.Prefix, pin.Path), b, 0700); e != nil {
			t.Fatal(e)
		}
		m.Files[i].SHA256 = hash(b)
		m.Files[i].Bytes = int64(len(b))
	}
	raw, _ := json.Marshal(m)
	if e := os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
	work := shortWorkRoot(t) // Retain this deliberately uncertain invocation.

	c := Config{WorkRoot: work, GateDir: work, Manifest: p, ManifestSHA256: hash(raw), Gate: []string{"/usr/bin/true"}, Whole: 4 * time.Second, Startup: time.Second, Stop: time.Second, LogBytes: 4096}
	r, e := Run(context.Background(), c)
	if e == nil || r.CleanupConfirmed || !strings.Contains(r.CleanupError, "shutdown deadline") {
		t.Fatal("forced shutdown became success", r, e)
	}
	if _, e := os.Stat(filepath.Join(r.Root, "intent.json")); e != nil {
		t.Fatal("original custody lost", e)
	}
	if _, e := os.Stat(filepath.Join(r.Root, "result.json")); e != nil {
		t.Fatal("uncertain result not retained", e)
	}
	t.Log("synthetic uncertain receipt retained at", r.Root)
}

func TestHardlinkAliasesMustAllBePinnedAndStayInsidePrefix(t *testing.T) {
	p, _, m := fixtureTools(t)
	alias := filepath.Join(m.Prefix, "psql-alias")
	if e := os.Link(filepath.Join(m.Prefix, "bin/psql"), alias); e != nil {
		t.Fatal(e)
	}
	m.Files[2].Links = 2
	a := m.Files[2]
	a.Path = "psql-alias"
	m.Files = append(m.Files, a)
	b, _ := json.Marshal(m)
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyTools(context.Background(), p, hash(b)); e != nil {
		t.Fatal("complete pinned internal aliases refused", e)
	}
	outside := filepath.Join(filepath.Dir(p), "outside-alias")
	if e := os.Link(alias, outside); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyTools(context.Background(), p, hash(b)); e == nil {
		t.Fatal("external mutable alias accepted")
	}
	// Even an updated nlink pin cannot disguise an alias outside the closure.
	m.Files[2].Links = 3
	m.Files[3].Links = 3
	b, _ = json.Marshal(m)
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyTools(context.Background(), p, hash(b)); e == nil {
		t.Fatal("uninventoried external alias accepted")
	}
}

func TestInvocationDirectoryReplacementCannotBecomeSameCustody(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "run")
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if e := boundDirectory(root, path); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(path, path+"-held"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e := boundDirectory(root, path); e == nil {
		t.Fatal("new directory adopted as original custody")
	}
}
