package releasefeed

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const admissionFile = "release-sequence"

// InitializeAdmission creates a private directory for a new producer under an
// existing owner-managed parent. Keep this directory across restarts and key
// rotations. Initialize only on first adoption, never to recover lost state.
func InitializeAdmission(dir, producer string) error {
	if !filepath.IsAbs(dir) || !producerID.MatchString(producer) {
		return errors.New("release admission requires an absolute directory and a valid producer")
	}
	dir = filepath.Clean(dir)
	parent, err := os.Open(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err := withAdmissionLock(dir, func(root *os.Root, lock *os.File) error {
		return persistSequence(root, lock, producer, 0)
	}); err != nil {
		return err
	}
	return parent.Sync()
}

// Activate verifies the selected release and uses the owner's trusted clock
// to check the signed validity interval. It holds the producer's admission
// lock, durably records the new high water mark, then calls activate
// synchronously. Use the same directory for every activation of this producer.
//
// A lower sequence is a rollback. An equal sequence is a repeat and never
// invokes activate, even if its original activation failed or was interrupted.
// Use Read for inspection and reconcile any uncertain effect at the owner.
// The callback must finish its activation before returning and honor ctx.
func Activate(ctx context.Context, src Source, trust Trust, sequence uint64, dir string, now func() time.Time, activate func(context.Context, Entry) error) error {
	if now == nil || activate == nil {
		return errors.New("release activation requires a clock and callback")
	}
	entry, err := Read(ctx, src, trust, sequence)
	if err != nil {
		return err
	}
	return withAdmissionLock(dir, func(root *os.Root, lock *os.File) error {
		last, err := readSequence(root, entry.Producer)
		if err != nil {
			return err
		}
		if last > entry.Sequence {
			return errors.New("release sequence rollback")
		}
		if last == entry.Sequence {
			return errors.New("release sequence already admitted")
		}
		if err := activationWindow(ctx, entry, now); err != nil {
			return err
		}
		if err := persistSequence(root, lock, entry.Producer, entry.Sequence); err != nil {
			return err
		}
		if err := activationWindow(ctx, entry, now); err != nil {
			return err
		}
		return activate(ctx, entry)
	})
}

func activationWindow(ctx context.Context, entry Entry, now func() time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t := now().Unix()
	if t < entry.IssuedAt || t >= entry.ExpiresAt {
		return errors.New("release outside signed validity interval")
	}
	return nil
}

func withAdmissionLock(dir string, action func(*os.Root, *os.File) error) error {
	if !filepath.IsAbs(dir) {
		return errors.New("release admission requires an absolute directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.Open(".")
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return errors.New("release admission requires a private owner directory")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("lock release admission: %w", err)
	}
	return action(root, lock)
}

func readSequence(root *os.Root, producer string) (uint64, error) {
	f, err := root.OpenFile(admissionFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, fmt.Errorf("open durable release sequence: %w", err)
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil {
		return 0, err
	}
	stat := i.Sys().(*syscall.Stat_t)
	if !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		return 0, errors.New("release sequence must be a private owner file")
	}
	prefix := "pomar.release-admission/v1\x00" + producer + "\x00"
	b, err := io.ReadAll(io.LimitReader(f, int64(len(prefix)+9)))
	if err != nil {
		return 0, err
	}
	if len(b) != len(prefix)+8 || string(b[:len(prefix)]) != prefix {
		return 0, errors.New("release admission state differs from expected producer or format")
	}
	return binary.BigEndian.Uint64(b[len(prefix):]), nil
}

func persistSequence(root *os.Root, dir *os.File, producer string, sequence uint64) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temp := ".sequence-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	b := binary.BigEndian.AppendUint64([]byte("pomar.release-admission/v1\x00"+producer+"\x00"), sequence)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	if err := root.Rename(temp, admissionFile); err != nil {
		return err
	}
	return dir.Sync()
}
