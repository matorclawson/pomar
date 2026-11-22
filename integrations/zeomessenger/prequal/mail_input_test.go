package prequal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/rodriveracom/pomar/internal/hostpolicy"
)

func mailInputFixture(t *testing.T) (*os.Root, MailInputRootBinding, string, []byte, string) {
	t.Helper()
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	// Remove inherited ACLs only from the fixture-owned directory before
	// creating descendants. Test cases add their own ACLs where needed.
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("/bin/chmod", "-N", parent).CombinedOutput(); err != nil {
			t.Fatalf("clear inherited fixture ACL: %v: %s", err, out)
		}
	}
	if e = os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(parent, "root")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	data := []byte("private mail plan fixture\n")
	path := filepath.Join(dir, "plan.json")
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	info, e := root.Stat(".")
	if e != nil {
		t.Fatal(e)
	}
	meta, e := mailInputMetadata(info)
	if e != nil {
		t.Fatal(e)
	}
	b := MailInputRootBinding{CanonicalPath: dir, Device: meta.Device, Inode: meta.Inode, OwnerUID: uint32(os.Geteuid()), HostControlsSHA256: strings.Repeat("a", 64)}
	parentInfo, e := os.Lstat(parent)
	if e != nil {
		t.Fatal(e)
	}
	parentMeta, e := mailInputAncestorMetadata(parentInfo)
	if e != nil {
		t.Fatal(e)
	}
	b.Ancestors = []MailInputAncestor{{CanonicalPath: parent, Metadata: parentMeta}}
	raw, e := json.Marshal(b.Ancestors)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	b.AncestorsSHA256 = hex.EncodeToString(sum[:])
	// This is a hermetic asserted host binding, not a claim that production
	// ancestor ACL establishment or custodian authority has been completed.
	h := sha256.Sum256(data)
	return root, b, path, data, hex.EncodeToString(h[:])
}

func requireMailInputRefusal(t *testing.T, data []byte, observation MailInputCustody, e error) {
	t.Helper()
	if e == nil || data != nil || !reflect.DeepEqual(observation, MailInputCustody{}) {
		t.Fatal("refusal returned bytes or a positive custody observation")
	}
}

// Positive controls verify the fixture's real owner, permissions and ACLs.
// The exported path still walks all host ancestors to the filesystem root.
func fixtureMailInputHooks(b MailInputRootBinding) mailInputHooks {
	return mailInputHooks{
		acl: hostpolicy.DescriptorACLSafe, ancestorACL: hostpolicy.DescriptorACLSafe,
		ancestorRoot: filepath.Dir(b.CanonicalPath),
	}
}

func acquireFixtureMailInput(root *os.Root, b MailInputRootBinding, name string, size int64, digest string) ([]byte, MailInputCustody, error) {
	return acquireMailInput(root, b, name, size, digest, fixtureMailInputHooks(b))
}

func TestMailInputAncestorSiblingChurnPreservesAcquisition(t *testing.T) {
	root, b, _, data, digest := mailInputFixture(t)
	sibling := filepath.Join(filepath.Dir(b.CanonicalPath), "unrelated-sibling")
	hooks := fixtureMailInputHooks(b)
	hooks.afterRead = func() {
		if e := os.WriteFile(sibling, []byte("unrelated"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	got, _, e := acquireMailInput(root, b, "plan.json", int64(len(data)), digest, hooks)
	if e != nil || !bytes.Equal(got, data) {
		t.Fatalf("unrelated ancestor entry invalidated input: %v", e)
	}
	if _, e := os.Stat(sibling); e != nil {
		t.Fatal("sibling creation was not exercised")
	}
}

func TestAcquireMailInputRequiresCompleteAncestorBinding(t *testing.T) {
	root, b, _, data, digest := mailInputFixture(t)
	got, proof, e := AcquireMailInput(root, b, "plan.json", int64(len(data)), digest)
	requireMailInputRefusal(t, got, proof, e)
}

func TestMailInputRejectsWritableAncestor(t *testing.T) {
	root, b, _, data, digest := mailInputFixture(t)
	parent := filepath.Dir(b.CanonicalPath)
	if e := os.Chmod(parent, 0770); e != nil {
		t.Fatal(e)
	}
	// Pin the new metadata so refusal exercises the permission policy
	// rather than a mismatch against the previous mode.
	info, e := os.Lstat(parent)
	if e != nil {
		t.Fatal(e)
	}
	b.Ancestors[0].Metadata, e = mailInputAncestorMetadata(info)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(b.Ancestors)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	b.AncestorsSHA256 = hex.EncodeToString(sum[:])
	got, proof, e := acquireFixtureMailInput(root, b, "plan.json", int64(len(data)), digest)
	requireMailInputRefusal(t, got, proof, e)
}

func TestMailInputAcquiresDescriptorBytes(t *testing.T) {
	root, b, path, want, digest := mailInputFixture(t)
	got, proof, e := acquireFixtureMailInput(root, b, filepath.Base(path), int64(len(want)), digest)
	if e != nil || !bytes.Equal(got, want) || proof.SHA256 != digest || proof.File.Links != 1 || proof.Root.Inode != b.Inode {
		t.Fatalf("safe descriptor acquisition: %v", e)
	}
	got[0] = 'X'
	raw, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(raw, want) {
		t.Fatal("returned buffer aliases source file")
	}
}

func TestMailInputAcceptsReadOnlySource(t *testing.T) {
	root, b, path, want, digest := mailInputFixture(t)
	if e := os.Chmod(path, 0400); e != nil {
		t.Fatal(e)
	}
	got, proof, e := acquireFixtureMailInput(root, b, "plan.json", int64(len(want)), digest)
	if e != nil || !bytes.Equal(got, want) || proof.File.Mode != 0400 {
		t.Fatalf("read-only control: %v", e)
	}
}

func TestMailInputRefusesNamesBeforeOpen(t *testing.T) {
	root, b, _, data, digest := mailInputFixture(t)
	for _, name := range []string{"", ".", "..", "/", "plan.json/child", "../plan.json", "a\x00b"} {
		opened := false
		hooks := fixtureMailInputHooks(b)
		hooks.beforeOpen = func() { opened = true }
		got, proof, e := acquireMailInput(root, b, name, int64(len(data)), digest, hooks)
		requireMailInputRefusal(t, got, proof, e)
		if opened {
			t.Fatal("invalid name reached open hook")
		}
	}
}

func TestMailInputRefusesUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"in-root symlink", "escaping symlink", "hardlink", "fifo", "directory", "group-write", "world-write", "world-read", "execute", "root-mode", "zero size", "oversize", "wrong digest", "changed inode binding"} {
		t.Run(kind, func(t *testing.T) {
			root, b, path, data, digest := mailInputFixture(t)
			size := int64(len(data))
			switch kind {
			case "in-root symlink":
				if e := os.Rename(path, path+".target"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("plan.json.target", path); e != nil {
					t.Fatal(e)
				}
			case "escaping symlink":
				os.Remove(path)
				if e := os.Symlink("../outside", path); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(path, path+".alias"); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				os.Remove(path)
				if e := syscall.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "directory":
				os.Remove(path)
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			case "group-write":
				os.Chmod(path, 0620)
			case "world-write":
				os.Chmod(path, 0602)
			case "world-read":
				os.Chmod(path, 0644)
			case "execute":
				os.Chmod(path, 0700)
			case "root-mode":
				os.Chmod(b.CanonicalPath, 0755)
			case "zero size":
				size = 0
			case "oversize":
				size = (64 << 10) + 1
			case "wrong digest":
				digest = strings.Repeat("0", 64)
			case "changed inode binding":
				b.Inode++
			}
			got, proof, e := acquireFixtureMailInput(root, b, "plan.json", size, digest)
			requireMailInputRefusal(t, got, proof, e)
		})
	}
}

func TestMailInputRefusesSubstitutionAndMutation(t *testing.T) {
	for _, kind := range []string{"symlink before open", "fifo before open", "file replacement", "same bytes rewritten", "unsafe final mode", "root replacement", "parent replacement", "ancestor record drift", "unknown ACL", "unknown file ACL", "unknown ancestor ACL"} {
		t.Run(kind, func(t *testing.T) {
			root, b, path, data, digest := mailInputFixture(t)
			hooks := fixtureMailInputHooks(b)
			switch kind {
			case "symlink before open":
				hooks.beforeOpen = func() {
					if e := os.Rename(path, path+".old"); e != nil {
						t.Fatal(e)
					}
					if e := os.Symlink("plan.json.old", path); e != nil {
						t.Fatal(e)
					}
				}
			case "fifo before open":
				hooks.beforeOpen = func() {
					if e := os.Remove(path); e != nil {
						t.Fatal(e)
					}
					if e := syscall.Mkfifo(path, 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "file replacement":
				hooks.afterRead = func() {
					if e := os.Rename(path, path+".old"); e != nil {
						t.Fatal(e)
					}
					if e := os.WriteFile(path, data, 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "same bytes rewritten":
				hooks.afterRead = func() {
					if e := os.WriteFile(path, data, 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "unsafe final mode":
				hooks.afterRead = func() {
					if e := os.Chmod(path, 0666); e != nil {
						t.Fatal(e)
					}
				}
			case "root replacement":
				hooks.afterRead = func() {
					if e := os.Rename(b.CanonicalPath, b.CanonicalPath+".old"); e != nil {
						t.Fatal(e)
					}
					if e := os.Mkdir(b.CanonicalPath, 0700); e != nil {
						t.Fatal(e)
					}
				}
			case "parent replacement":
				hooks.afterRead = func() {
					parent := filepath.Dir(b.CanonicalPath)
					if e := os.Rename(parent, parent+".old"); e != nil {
						t.Fatal(e)
					}
					t.Cleanup(func() { os.RemoveAll(parent); os.Rename(parent+".old", parent) })
					if e := os.MkdirAll(b.CanonicalPath, 0700); e != nil {
						t.Fatal(e)
					}
				}
			case "ancestor record drift":
				b.Ancestors[len(b.Ancestors)-1].Metadata.Inode++
				raw, _ := json.Marshal(b.Ancestors)
				h := sha256.Sum256(raw)
				b.AncestorsSHA256 = hex.EncodeToString(h[:])
			case "unknown ACL":
				hooks.acl = func(*os.File) bool { return false }
			case "unknown ancestor ACL":
				hooks.ancestorACL = func(*os.File) bool { return false }
			case "unknown file ACL":
				hooks.acl = func(f *os.File) bool { info, e := f.Stat(); return e == nil && info.IsDir() }
			}
			got, proof, e := acquireMailInput(root, b, "plan.json", int64(len(data)), digest, hooks)
			requireMailInputRefusal(t, got, proof, e)
		})
	}
}
