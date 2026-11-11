package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
)

var artifactName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func exportArtifact(root *os.Root, name string, maximum int64, uid uint32, out io.Writer) error {
	if !artifactName.MatchString(name) || strings.Contains(name, "..") || maximum <= 0 || maximum > 1<<30 {
		return fmt.Errorf("invalid artifact export bounds")
	}
	namespace, e := root.Lstat(name)
	if e != nil {
		return e
	}
	if !namespace.Mode().IsRegular() {
		return fmt.Errorf("artifact leaf must not be a symlink or special file")
	}
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return e
	}
	if !os.SameFile(namespace, before) {
		return fmt.Errorf("artifact namespace changed before open")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || owner.Nlink != 1 || owner.Uid != uid || before.Size() > maximum {
		return fmt.Errorf("artifact must be a bounded single-link job-owned regular file")
	}
	scan := func(emit bool) (string, error) {
		h := sha256.New()
		var count int64
		buffer := make([]byte, 64<<10)
		for {
			left := before.Size() - count
			limit := int64(len(buffer))
			if limit > left+1 {
				limit = left + 1
			}
			n, err := f.Read(buffer[:int(limit)])
			if int64(n) > left {
				return "", fmt.Errorf("artifact overrun")
			}
			if n > 0 {
				h.Write(buffer[:n])
				count += int64(n)
				if emit {
					written, e := out.Write(buffer[:n])
					if e != nil {
						return "", e
					}
					if written != n {
						return "", io.ErrShortWrite
					}
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", err
			}
			if n == 0 {
				return "", io.ErrNoProgress
			}
		}
		named, e := root.Lstat(name)
		if e != nil {
			return "", e
		}
		if !named.Mode().IsRegular() || !os.SameFile(namespace, named) {
			return "", fmt.Errorf("artifact namespace changed")
		}
		after, e := f.Stat()
		if e != nil {
			return "", e
		}
		owner, ok := after.Sys().(*syscall.Stat_t)
		if !ok || owner.Nlink != 1 || owner.Uid != uid || !os.SameFile(before, after) || count != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			return "", fmt.Errorf("artifact changed")
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	first, e := scan(false)
	if e != nil {
		return e
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	header := fmt.Sprintf("POMAR_ARTIFACT_V1 %s %d %s\n", name, before.Size(), first)
	if written, err := io.WriteString(out, header); err != nil {
		return err
	} else if written != len(header) {
		return io.ErrShortWrite
	}
	second, e := scan(true)
	if e != nil {
		return e
	}
	if second != first {
		return fmt.Errorf("artifact changed")
	}
	if e = f.Close(); e != nil {
		return e
	}
	footer := "\nPOMAR_ARTIFACT_END\n"
	n, e := io.WriteString(out, footer)
	if e != nil {
		return e
	}
	if n != len(footer) {
		return io.ErrShortWrite
	}
	return nil
}
