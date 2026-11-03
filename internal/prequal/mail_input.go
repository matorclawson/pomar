package prequal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/zeroemployeeorg/pomar/internal/hostpolicy"
)

// MailInputRootBinding comes from the owner's independently admitted host
// control record. Establishment MUST check every ancestor's owner, mode, ACL
// and identity. This reader trusts that establishment; it does not turn these
// caller-supplied digests into ancestor evidence or custodian authority.
// Neither the binding nor the held root may be selected by guest JSON.
type MailInputRootBinding struct {
	CanonicalPath      string              `json:"canonical_path"`
	Device             uint64              `json:"device"`
	Inode              uint64              `json:"inode"`
	OwnerUID           uint32              `json:"owner_uid"`
	AncestorsSHA256    string              `json:"ancestors_sha256"`
	HostControlsSHA256 string              `json:"host_controls_sha256"`
	Ancestors          []MailInputAncestor `json:"ancestors"`
}

type MailInputAncestor struct {
	CanonicalPath string                    `json:"canonical_path"`
	Metadata      MailInputAncestorMetadata `json:"metadata"`
}

// Ancestor directory entry churn is unrelated to custody of this input.
// Bind only identity/permissions; inspect ACLs on held descriptors each time.
type MailInputAncestorMetadata struct {
	Device, Inode uint64
	UID, GID      uint32
	Mode          os.FileMode
}

type MailInputMetadata struct {
	Device, Inode         uint64
	UID, GID              uint32
	Links                 uint64
	Mode                  os.FileMode
	Size                  int64
	ModifiedNS            int64
	ChangedSec, ChangedNS int64
}

type MailInputCustody struct {
	RootBinding MailInputRootBinding
	Root        MailInputMetadata
	File        MailInputMetadata
	SHA256      string
}

// AcquireMailInput returns exact held-descriptor bytes only after all checks.
// The owner must stage this returned buffer, never reopen the source pathname.
// Backend read-only mapping, receipt authority and post-run checks are separate.
// Source files must be private0400/0600 and the established root private0700.
func AcquireMailInput(root *os.Root, binding MailInputRootBinding, name string, size int64, digest string) ([]byte, MailInputCustody, error) {
	return acquireMailInput(root, binding, name, size, digest, mailInputHooks{acl: hostpolicy.DescriptorACLSafe, ancestorACL: hostpolicy.DescriptorACLSafe})
}

// Fault/unknown-metadata seams are package-private and never caller options.
type mailInputHooks struct {
	acl                   func(*os.File) bool
	ancestorACL           func(*os.File) bool
	beforeOpen, afterRead func()
}

var errMailInputCustody = errors.New("mail input custody unavailable or changed")

func acquireMailInput(root *os.Root, binding MailInputRootBinding, name string, size int64, digest string, hooks mailInputHooks) ([]byte, MailInputCustody, error) {
	fail := func() ([]byte, MailInputCustody, error) { return nil, MailInputCustody{}, errMailInputCustody }
	if root == nil || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || size < 1 || size > 64<<10 || !sha.MatchString(digest) || hooks.acl == nil || hooks.ancestorACL == nil {
		return fail()
	}
	if !filepath.IsAbs(binding.CanonicalPath) || filepath.Clean(binding.CanonicalPath) != binding.CanonicalPath || root.Name() != binding.CanonicalPath || binding.OwnerUID != uint32(os.Geteuid()) || !sha.MatchString(binding.AncestorsSHA256) || !sha.MatchString(binding.HostControlsSHA256) {
		return fail()
	}
	dir, e := root.Open(".")
	if e != nil {
		return fail()
	}
	defer dir.Close()
	rootBefore, e := checkMailInputRoot(root, dir, binding, hooks.acl, hooks.ancestorACL)
	if e != nil {
		return fail()
	}
	before, e := root.Lstat(name)
	if e != nil {
		return fail()
	}
	fileBefore, e := mailInputMetadata(before)
	if e != nil || !safeMailInputFile(fileBefore, size) {
		return fail()
	}
	if hooks.beforeOpen != nil {
		hooks.beforeOpen()
	}
	// os.Root may follow an in-root symlink even with O_NOFOLLOW. Lstat above,
	// descriptor SameFile below and the final Lstat are all necessary.
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return fail()
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return fail()
	}
	current, e := mailInputMetadata(opened)
	if e != nil || current != fileBefore || !safeMailInputFile(current, size) || !hooks.acl(f) {
		return fail()
	}
	data, e := io.ReadAll(io.LimitReader(f, size+1))
	if e != nil || int64(len(data)) != size {
		return fail()
	}
	if hooks.afterRead != nil {
		hooks.afterRead()
	}
	finalInfo, e := f.Stat()
	if e != nil {
		return fail()
	}
	final, e := mailInputMetadata(finalInfo)
	if e != nil || final != fileBefore || !safeMailInputFile(final, size) || !hooks.acl(f) {
		return fail()
	}
	pathInfo, e := root.Lstat(name)
	if e != nil || !os.SameFile(finalInfo, pathInfo) {
		return fail()
	}
	pathFinal, e := mailInputMetadata(pathInfo)
	if e != nil || pathFinal != final {
		return fail()
	}
	rootAfter, e := checkMailInputRoot(root, dir, binding, hooks.acl, hooks.ancestorACL)
	if e != nil || rootAfter != rootBefore {
		return fail()
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return fail()
	}
	return data, MailInputCustody{RootBinding: binding, Root: rootBefore, File: final, SHA256: digest}, nil
}

func safeMailInputFile(m MailInputMetadata, size int64) bool {
	return m.Mode.IsRegular() && (m.Mode == 0400 || m.Mode == 0600) && m.UID == uint32(os.Geteuid()) && m.Links == 1 && m.Size == size
}

func checkMailInputRoot(root *os.Root, dir *os.File, binding MailInputRootBinding, acl, ancestorACL func(*os.File) bool) (MailInputMetadata, error) {
	var zero MailInputMetadata
	if !mailInputAncestorsMatch(binding, ancestorACL) {
		return zero, errMailInputCustody
	}
	canonical, e := filepath.EvalSymlinks(binding.CanonicalPath)
	if e != nil || canonical != binding.CanonicalPath {
		return zero, errMailInputCustody
	}
	held, e := dir.Stat()
	if e != nil {
		return zero, e
	}
	path, e := os.Lstat(binding.CanonicalPath)
	if e != nil || !os.SameFile(held, path) {
		return zero, errMailInputCustody
	}
	dot, e := root.Stat(".")
	if e != nil || !os.SameFile(held, dot) {
		return zero, errMailInputCustody
	}
	m, e := mailInputMetadata(held)
	if e != nil || m.Mode != os.ModeDir|0700 || m.UID != binding.OwnerUID || m.Device != binding.Device || m.Inode != binding.Inode || !acl(dir) {
		return zero, errMailInputCustody
	}
	return m, nil
}

func mailInputAncestorsMatch(binding MailInputRootBinding, acl func(*os.File) bool) bool {
	if len(binding.Ancestors) == 0 || len(binding.Ancestors) > 128 || len(binding.CanonicalPath) > 4096 {
		return false
	}
	encoded, e := json.Marshal(binding.Ancestors)
	if e != nil {
		return false
	}
	h := sha256.Sum256(encoded)
	if hex.EncodeToString(h[:]) != binding.AncestorsSHA256 {
		return false
	}
	var paths []string
	for p := filepath.Dir(binding.CanonicalPath); ; p = filepath.Dir(p) {
		paths = append(paths, p)
		if p == filepath.Dir(p) {
			break
		}
	}
	if len(paths) != len(binding.Ancestors) {
		return false
	}
	for i, path := range paths {
		expected := binding.Ancestors[len(paths)-1-i]
		if expected.CanonicalPath != path {
			return false
		}
		info, e := os.Lstat(path)
		if e != nil {
			return false
		}
		meta, e := mailInputAncestorMetadata(info)
		if e != nil || meta != expected.Metadata || !meta.Mode.IsDir() || meta.Mode.Perm()&0022 != 0 || (meta.UID != 0 && meta.UID != uint32(os.Geteuid())) {
			return false
		}
		if !mailInputAncestorDescriptorMatches(path, info, expected.Metadata, acl) {
			return false
		}
	}
	return true
}

func mailInputAncestorDescriptorMatches(path string, before os.FileInfo, expected MailInputAncestorMetadata, acl func(*os.File) bool) bool {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
	if e != nil {
		return false
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return false
	}
	m, e := mailInputAncestorMetadata(opened)
	if e != nil || m != expected || !acl(f) {
		return false
	}
	after, e := f.Stat()
	if e != nil {
		return false
	}
	m, e = mailInputAncestorMetadata(after)
	pathAfter, e2 := os.Lstat(path)
	if e != nil || e2 != nil || m != expected || !os.SameFile(after, pathAfter) {
		return false
	}
	pathMeta, e := mailInputAncestorMetadata(pathAfter)
	return e == nil && pathMeta == expected
}

func mailInputAncestorMetadata(info os.FileInfo) (MailInputAncestorMetadata, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return MailInputAncestorMetadata{}, errMailInputCustody
	}
	return MailInputAncestorMetadata{Device: uint64(st.Dev), Inode: uint64(st.Ino), UID: st.Uid, GID: st.Gid, Mode: info.Mode()}, nil
}

func mailInputMetadata(info os.FileInfo) (MailInputMetadata, error) {
	var zero MailInputMetadata
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return zero, errMailInputCustody
	}
	sec, ns, ok := mailInputChangeTime(st)
	if !ok {
		return zero, errMailInputCustody
	}
	return MailInputMetadata{Device: uint64(st.Dev), Inode: uint64(st.Ino), UID: st.Uid, GID: st.Gid, Links: uint64(st.Nlink), Mode: info.Mode(), Size: info.Size(), ModifiedNS: info.ModTime().UnixNano(), ChangedSec: sec, ChangedNS: ns}, nil
}
