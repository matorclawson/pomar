package manager

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// peerUID reads the kernel's credentials for a connected Unix socket.
func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("manager: not a Unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		cred, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, fmt.Errorf("manager: SO_PEERCRED: %w", socketErr)
	}
	if cred == nil || cred.Pid <= 0 {
		return 0, errors.New("manager: Unix peer credentials unavailable")
	}
	return cred.Uid, nil
}
