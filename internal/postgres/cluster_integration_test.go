package postgres

// sow: pomar-SOW-87 rev39. Opt-in real tool tests; never an installed service.
import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func realConfig(t *testing.T) Config {
	t.Helper()
	p, h := os.Getenv("POMAR_POSTGRES_TEST_MANIFEST"), os.Getenv("POMAR_POSTGRES_TEST_MANIFEST_SHA256")
	if p == "" || h == "" {
		t.Skip("explicit independently pinned existing tools required; no runtime downloads")
	}
	work := shortWorkRoot(t) // Retain data/metadata even after successful cleanup.
	return Config{WorkRoot: work, GateDir: work, Manifest: p, ManifestSHA256: h, Whole: time.Minute, Startup: 20 * time.Second, Stop: 5 * time.Second, LogBytes: 1 << 20, Extensions: map[string]string{"uuid-ossp": "1.1"}}
}
func TestRealConcurrentClustersUsePrivateSocketsAndRealExtensions(t *testing.T) {
	c := realConfig(t)
	tools, e := VerifyTools(context.Background(), c.Manifest, c.ManifestSHA256)
	if e != nil {
		t.Fatal(e)
	}
	c.Gate = []string{"/bin/sh", "-c", `test -z "${AWS_SECRET_ACCESS_KEY+x}" && exec "$1" -X -v ON_ERROR_STOP=1 -Atc "$2"`, "fixture", filepath.Join(tools.Prefix, "bin/psql"), `CREATE TABLE marker AS SELECT 1; SELECT length(uuid_generate_v4()::text)=36, current_setting('listen_addresses')='', inet_server_addr() IS NULL;`}
	t.Setenv("AWS_SECRET_ACCESS_KEY", "not-forwarded")
	type outcome struct {
		r Result
		e error
	}
	done := make(chan outcome, 2)
	for range 2 {
		go func() { r, e := Run(context.Background(), c); done <- outcome{r, e} }()
	}
	roots := map[string]bool{}
	for range 2 {
		o := <-done
		if o.e != nil || !o.r.CleanupConfirmed || !o.r.LogsComplete || o.r.GateExit == nil || *o.r.GateExit != 0 {
			t.Fatal(o.r, o.e)
		}
		if roots[o.r.Root] {
			t.Fatal("cluster root reused")
		}
		roots[o.r.Root] = true
		b, e := os.ReadFile(filepath.Join(o.r.Root, "gate.stdout"))
		if e != nil || !strings.Contains(string(b), "t|t|t") {
			t.Fatal("real UUID/noTCP/Unix-socket assertion missing", string(b), e)
		}
		t.Log("retained qualified invocation", o.r.Root)
	}
}
func TestRealGateFailureAndCancellationKeepSeparateCleanupResults(t *testing.T) {
	base := realConfig(t)
	for _, mode := range []string{"exit7", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c := base
			c.WorkRoot = shortWorkRoot(t)
			c.GateDir = c.WorkRoot
			c.Gate = []string{"/bin/sh", "-c", "exit 7"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				c.Gate = []string{"/bin/sleep", "30"}
				go func() {
					deadline := time.Now().Add(30 * time.Second)
					for time.Now().Before(deadline) {
						entries, _ := os.ReadDir(c.WorkRoot)
						for _, entry := range entries {
							if _, e := os.Stat(filepath.Join(c.WorkRoot, entry.Name(), "gate-intent.json")); e == nil {
								cancel()
								return
							}
						}
						time.Sleep(10 * time.Millisecond)
					}
					cancel()
				}()
			}
			r, e := Run(ctx, c)
			if e == nil || !r.CleanupConfirmed || r.GateExit == nil || *r.GateExit == 0 {
				t.Fatal("failure/cancel lost custody separation", r, e)
			}
			if mode == "exit7" && *r.GateExit != 7 {
				t.Fatal("gate exit changed", r)
			}
			raw, re := os.ReadFile(filepath.Join(r.Root, "result.json"))
			if re != nil || !strings.Contains(string(raw), `"cleanup_confirmed":true`) {
				t.Fatal("cleanup receipt absent", string(raw), re)
			}
			t.Log(fmt.Sprintf("%s retained %s", mode, r.Root))
		})
	}
}

func shortWorkRoot(t *testing.T) string {
	t.Helper()
	p := filepath.Join(os.TempDir(), rand.Text()[:8])
	if e := os.Mkdir(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}

func TestRealVaultFixtureEncryptDecryptAndCleanup(t *testing.T) {
	path, h := os.Getenv("POMAR_POSTGRES_VAULT_TEST_MANIFEST"), os.Getenv("POMAR_POSTGRES_VAULT_TEST_MANIFEST_SHA256")
	if path == "" || h == "" {
		t.Skip("explicit genuine Vault prefix and separate admitted native original required")
	}
	tools, e := VerifyTools(context.Background(), path, h)
	if e != nil {
		t.Fatal(e)
	}
	if tools.FixtureProfile != vaultFixtureProfile {
		t.Fatal("genuine fixed Vault profile required")
	}
	work := shortWorkRoot(t)
	sql := `CREATE SCHEMA extensions; CREATE EXTENSION pgcrypto WITH SCHEMA extensions; SELECT vault.create_secret('synthetic-only', 'fixture'); SELECT decrypted_secret = 'synthetic-only' FROM vault.decrypted_secrets WHERE name='fixture'; SELECT extensions.digest('fixture','sha256') IS NOT NULL, length(extensions.gen_random_uuid()::text)=36; SELECT current_setting('server_version_num')='170011', (SELECT extversion='0.3.1' FROM pg_extension WHERE extname='supabase_vault'), (SELECT extversion='1.3' FROM pg_extension WHERE extname='pgcrypto');`
	c := Config{WorkRoot: work, GateDir: work, Manifest: path, ManifestSHA256: h, Whole: time.Minute, Startup: 20 * time.Second, Stop: 10 * time.Second, LogBytes: 1 << 20, Extensions: map[string]string{"supabase_vault": "0.3.1"}, Gate: []string{filepath.Join(tools.Prefix, "bin/psql"), "-X", "-v", "ON_ERROR_STOP=1", "-Atc", sql}}
	r, e := Run(context.Background(), c)
	if e != nil || !r.CleanupConfirmed || r.GateExit == nil || *r.GateExit != 0 {
		t.Fatal("real Vault smoke/cleanup failed", r, e)
	}
	out, e := os.ReadFile(filepath.Join(r.Root, "gate.stdout"))
	if e != nil || (!strings.Contains(string(out), "\nt\nt|t\n") || !strings.Contains(string(out), "\nt|t|t\n")) {
		t.Fatal("real encryption/digest/UUID observations missing", e)
	}
	for _, name := range []string{"vault-root-key", "vault-getkey"} {
		if _, e := os.Lstat(filepath.Join(r.Root, name)); !os.IsNotExist(e) {
			t.Fatal("fixture secret retained after confirmed shutdown", e)
		}
	}
}
