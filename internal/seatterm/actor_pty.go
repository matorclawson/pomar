package seatterm

import (
	"os"
	"syscall"
)

// ActorPTY allocates a separate controlling terminal for a fixed guest actor.
// The caller owns the master; the unprivileged child inherits only the slave.
// No terminal emulator runs here and no bytes are interpreted.
func ActorPTY(cols, rows uint16) (*os.File, *os.File, error) {
	master, path, err := openPTY()
	if err != nil {
		return nil, nil, err
	}
	slave, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err == nil {
		err = setSize(slave, cols, rows)
	}
	if err != nil {
		master.Close()
		if slave != nil {
			slave.Close()
		}
		return nil, nil, err
	}
	return master, slave, nil
}
