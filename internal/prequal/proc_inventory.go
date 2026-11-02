package prequal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// PF_KTHREAD is a kernel identity bit, not the process's mutable comm/argv.
// Linux include/linux/sched.h; stat fields are specified by proc_pid_stat(5).
const kernelThreadFlag = uint64(0x00200000)
const maxProcMetadata = 64 << 10
const maxProcEntries = 65536

type procIdentity struct {
	row   ProcessRow
	birth uint64
}

// collectProc is private so production callers cannot substitute a proc root.
// between is only a fixture seam; production always supplies nil.
func collectProc(ctx context.Context, path, scope string, between func(int) error) (ProcessSnapshot, error) {
	empty := ProcessSnapshot{}
	if scope == "" || len(scope) > 256 {
		return empty, errors.New("bounded original scope required")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	ids, err := procIDs(ctx, root)
	if err != nil {
		return empty, err
	}
	out := ProcessSnapshot{ScopeID: scope, Rows: make([]ProcessRow, 0, len(ids))}
	for _, pid := range ids {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		dir, err := root.OpenRoot(strconv.Itoa(pid))
		if err != nil {
			return empty, fmt.Errorf("pid %d disappeared: %w", pid, err)
		}
		first, e := readProcIdentity(dir, pid)
		if e == nil && between != nil {
			e = between(pid)
		}
		var second procIdentity
		if e == nil {
			second, e = readProcIdentity(dir, pid)
		}
		dir.Close()
		if e != nil {
			return empty, fmt.Errorf("pid %d inventory: %w", pid, e)
		}
		if first != second {
			return empty, fmt.Errorf("pid %d identity changed during inventory", pid)
		}
		out.Rows = append(out.Rows, second.row)
	}
	after, err := procIDs(ctx, root)
	if err != nil {
		return empty, err
	}
	if len(ids) != len(after) {
		return empty, errors.New("process set changed during inventory")
	}
	for i := range ids {
		if ids[i] != after[i] {
			return empty, errors.New("process set changed during inventory")
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return out, nil
}

func procIDs(ctx context.Context, root *os.Root) ([]int, error) {
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var ids []int
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, e := f.ReadDir(128)
		for _, d := range entries {
			count++
			if count > maxProcEntries {
				return nil, errors.New("proc directory exceeds inventory bound")
			}
			n := d.Name()
			if n == "" || strings.IndexFunc(n, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				continue
			}
			pid, err := strconv.Atoi(n)
			if err != nil || pid < 1 || strconv.Itoa(pid) != n || !d.IsDir() || d.Type()&os.ModeSymlink != 0 {
				return nil, errors.New("invalid proc pid directory")
			}
			ids = append(ids, pid)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
	}
	if len(ids) == 0 {
		return nil, errors.New("empty proc inventory")
	}
	sort.Ints(ids)
	return ids, nil
}
func procBytes(dir *os.Root, name string) ([]byte, error) {
	f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("proc metadata is not regular")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxProcMetadata+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxProcMetadata {
		return nil, errors.New("proc metadata exceeds bound")
	}
	return b, nil
}
func readProcIdentity(dir *os.Root, pid int) (procIdentity, error) {
	var out procIdentity
	b, err := procBytes(dir, "stat")
	if err != nil {
		return out, err
	}
	// comm may contain spaces, newlines and closing parentheses. Fields after
	// its final ')' are numeric except the state; never use comm as identity.
	s := string(b)
	open := strings.Index(s, " (")
	close := strings.LastIndex(s, ") ")
	if open < 1 || close < open+2 || s[:open] != strconv.Itoa(pid) {
		return out, errors.New("malformed proc stat pid/comm")
	}
	fields := strings.Fields(s[close+2:])
	if len(fields) < 20 || len(fields[0]) != 1 {
		return out, errors.New("short proc stat")
	}
	flags, e1 := strconv.ParseUint(fields[6], 10, 64)
	birth, e2 := strconv.ParseUint(fields[19], 10, 64)
	if e1 != nil || e2 != nil {
		return out, errors.New("malformed proc flags/birth")
	}
	b, err = procBytes(dir, "status")
	if err != nil {
		return out, err
	}
	uid := -1
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		if uid >= 0 {
			return out, errors.New("duplicate proc uid")
		}
		f := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(f) != 4 {
			return out, errors.New("malformed proc uid")
		}
		for i, n := range f {
			v, e := strconv.ParseUint(n, 10, 32)
			if e != nil || v > 2147483647 {
				return out, errors.New("invalid proc uid")
			}
			if i == 0 {
				uid = int(v)
			} else if int(v) != uid {
				return out, errors.New("transitional proc uid")
			}
		}
	}
	if uid < 0 {
		return out, errors.New("missing proc uid")
	}
	exe, err := dir.Readlink("exe")
	kernel := flags&kernelThreadFlag != 0
	if kernel {
		if !errors.Is(err, os.ErrNotExist) || uid != 0 {
			return out, errors.New("inconsistent kernel process metadata")
		}
		exe = ""
	} else if err != nil || len(exe) == 0 || len(exe) > maxProcMetadata || !strings.HasPrefix(exe, "/") {
		return out, errors.New("full proc executable unavailable")
	}
	out = procIdentity{row: ProcessRow{PID: pid, UID: uid, Exe: exe, KernelThread: kernel}, birth: birth}
	return out, nil
}
