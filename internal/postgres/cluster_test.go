package postgres

// sow: pomar-SOW-87 rev39. Synthetic pins never imply installed tool authority.
import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
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

func fixtureVaultTools(t *testing.T) (string, string, Tools) {
	t.Helper()
	path, _, m := fixtureTools(t)
	m.FixtureProfile = vaultFixtureProfile
	for _, name := range vaultFixtureFiles {
		b := []byte("synthetic nonexecuted Vault closure\n")
		if strings.HasSuffix(name, ".control") {
			b = []byte("default_version = '0.3.1'\nmodule_pathname = '$libdir/supabase_vault'\nschema = vault\nrelocatable = false\n")
		}
		p := filepath.Join(m.Prefix, name)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		m.Files = append(m.Files, FilePin{Path: name, SHA256: hash(b), Bytes: int64(len(b)), Mode: 0600})
	}
	b, _ := json.Marshal(m)
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	return path, hash(b), m
}

func TestVaultFixedProfileRequiresExactPinnedClosureAndControl(t *testing.T) {
	for _, change := range []string{"none", "unknown-profile", "wrong-server", "missing-upgrade", "wrong-control", "duplicate-control"} {
		t.Run(change, func(t *testing.T) {
			path, _, m := fixtureVaultTools(t)
			switch change {
			case "unknown-profile":
				m.FixtureProfile = "caller-selected-command"
			case "wrong-server":
				m.Version = "17.12"
			case "missing-upgrade":
				m.Files = m.Files[:len(m.Files)-1]
			case "wrong-control", "duplicate-control":
				for i, p := range m.Files {
					if !strings.HasSuffix(p.Path, ".control") {
						continue
					}
					b, e := os.ReadFile(filepath.Join(m.Prefix, p.Path))
					if e != nil {
						t.Fatal(e)
					}
					if change == "wrong-control" {
						b = bytes.Replace(b, []byte("schema = vault"), []byte("schema = elsewhere"), 1)
					} else {
						b = append(b, []byte("schema = vault\n")...)
					}
					if e := os.WriteFile(filepath.Join(m.Prefix, p.Path), b, 0600); e != nil {
						t.Fatal(e)
					}
					m.Files[i].Bytes, m.Files[i].SHA256 = int64(len(b)), hash(b)
				}
			}
			b, _ := json.Marshal(m)
			if e := os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			_, e := VerifyTools(context.Background(), path, hash(b))
			if (change == "none") != (e == nil) {
				t.Fatal("fixed profile closure decision differs", change, e)
			}
		})
	}
}

func TestVaultFixedProfileRefusesMissingRequestBeforeInvocation(t *testing.T) {
	path, h, _ := fixtureVaultTools(t)
	work, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	c := Config{Manifest: path, ManifestSHA256: h, WorkRoot: work, GateDir: work, Gate: []string{"/nonexecuted"}, Whole: time.Minute, Startup: time.Second, Stop: time.Second, LogBytes: 4096}
	if _, e := Run(context.Background(), c); e == nil || !strings.Contains(e.Error(), "explicit supabase_vault") {
		t.Fatal("missing explicit request did not refuse before start", e)
	}
	entries, e := os.ReadDir(work)
	if e != nil || len(entries) != 0 {
		t.Fatal("refusal created an invocation", e)
	}
}

func TestVaultHelperPathRejectsShellInjectionAndDefaultsDoNotPreload(t *testing.T) {
	for _, path := range []string{"relative", "/a/../b", "/a b", "/a;touch", "/a$(id)", "/a'quote", "/a\nline", "/a`id`"} {
		if vaultPath(path) {
			t.Fatal("shell-unsafe path accepted")
		}
	}
	if !vaultPath("/owned/run-01_a.b") {
		t.Fatal("safe owned path refused")
	}
	if strings.Contains(strings.Join(postgresArgs("/owned/run", "/owned/run/s", false), " "), "vault") {
		t.Fatal("default profile preloads Vault")
	}
	args := strings.Join(postgresArgs("/owned/run", "/owned/run/s", true), " ")
	if !strings.Contains(args, "shared_preload_libraries=supabase_vault") || !strings.Contains(args, "vault.getkey_script=/owned/run/vault-getkey") {
		t.Fatal("fixed preload arguments missing")
	}
}

func ownedVaultFixture(t *testing.T) (*os.Root, string, *vaultFixture) {
	t.Helper()
	// Canonicalize the fixture parent only; retain the real path identity.
	path, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = root.Close() })
	f, e := prepareVaultFixture(root, path)
	if e != nil {
		t.Fatal(e)
	}
	return root, path, f
}

func TestVaultSyntheticKeyHelperAndConfirmedCleanup(t *testing.T) {
	root, path, f := ownedVaultFixture(t)
	if e := f.verify(root, path); e != nil {
		t.Fatal(e)
	}
	key, e := os.ReadFile(filepath.Join(path, "vault-root-key"))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	b, e := hex.DecodeString(strings.TrimSpace(string(key)))
	if e != nil || len(b) != 32 {
		t.Fatal("invalid synthetic key protocol")
	}
	clear(b)
	// Exercise only our newly generated fixed helper; never a private owner key.
	got, e := exec.Command(filepath.Join(path, "vault-getkey")).Output()
	if e != nil || !bytes.Equal(got, key) {
		clear(got)
		t.Fatal("fixed helper did not return the original synthetic key")
	}
	clear(got)
	intent, e := os.ReadFile(filepath.Join(path, "vault-fixture-intent.json"))
	if e != nil || bytes.Contains(intent, bytes.TrimSpace(key)) || !bytes.Contains(intent, []byte(vaultFixtureProfile)) {
		t.Fatal("intent missing or contains private bytes")
	}
	if e := f.cleanup(root, path, false); e == nil {
		t.Fatal("uncertain original allowed key deletion")
	}
	if e := f.verify(root, path); e != nil {
		t.Fatal("uncertain custody changed", e)
	}
	if e := f.cleanup(root, path, true); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"vault-root-key", "vault-getkey"} {
		if _, e := root.Lstat(name); !os.IsNotExist(e) {
			t.Fatal("confirmed shutdown retained key/helper", e)
		}
	}
	if _, e := root.Lstat("vault-fixture-intent.json"); e != nil {
		t.Fatal("nonsecret evidence removed", e)
	}
	if _, e := prepareVaultFixture(root, path); e == nil {
		t.Fatal("original intent reused")
	}
}

func TestVaultNewClustersNeverReuseKeysAndReplacementRefusesCleanup(t *testing.T) {
	root, path, f := ownedVaultFixture(t)
	_, otherPath, other := ownedVaultFixture(t)
	if f.keyHash == other.keyHash {
		t.Fatal("new cluster reused key")
	}
	out := filepath.Join(otherPath, "do-not-remove")
	if e := os.WriteFile(out, []byte("unrelated"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := root.Remove("vault-getkey"); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(out, filepath.Join(path, "vault-getkey")); e != nil {
		t.Fatal(e)
	}
	if e := f.cleanup(root, path, true); e == nil {
		t.Fatal("replaced helper authorized deletion")
	}
	if b, e := os.ReadFile(out); e != nil || string(b) != "unrelated" {
		t.Fatal("unrelated file changed")
	}
	if _, e := root.Lstat("vault-root-key"); e != nil {
		t.Fatal("uncertain replacement removed private original", e)
	}
}

func TestVaultCleanupHoldsChangedKeyCustody(t *testing.T) {
	for _, change := range []string{"bytes", "mode", "hardlink"} {
		t.Run(change, func(t *testing.T) {
			root, path, f := ownedVaultFixture(t)
			key := filepath.Join(path, "vault-root-key")
			switch change {
			case "bytes":
				if e := os.WriteFile(key, []byte(strings.Repeat("0", 64)+"\n"), 0600); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := os.Chmod(key, 0644); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(key, filepath.Join(path, "unapproved-alias")); e != nil {
					t.Fatal(e)
				}
			}
			if e := f.cleanup(root, path, true); e == nil {
				t.Fatal("changed private custody accepted", change)
			}
			for _, name := range []string{"vault-root-key", "vault-getkey"} {
				if _, e := root.Lstat(name); e != nil {
					t.Fatal("uncertain cleanup removed original state", e)
				}
			}
		})
	}
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
