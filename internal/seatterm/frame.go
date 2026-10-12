// Package seatterm carries an interactive seat's terminal: a bounded,
// typed byte stream between the operator's attach client and a PTY in the
// seat's guest (POMAR-CC SOW 15 §5, as corrected by SOW 16 §3). It carries
// keystrokes, screen bytes and window size, and nothing else: no files, no
// ports, no command but the fixed one it is given. Nothing it carries is
// recorded.
package seatterm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Protocol is the upgrade token for the stream.
const Protocol = "pomar-terminal/v1"

// Frame types.
const (
	Data   byte = 'd' // terminal bytes, either direction
	Resize byte = 'r' // client to guest: columns and rows, two big-endian uint16
	Close  byte = 'x' // either side: the stream ends
)

// MaxData bounds one data frame's payload.
const MaxData = 32 << 10

// Window size bounds.
const (
	MaxCols = 1000
	MaxRows = 500
)

// WriteFrame writes one frame: its type, a big-endian uint16 length, and
// the payload.
func WriteFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > MaxData {
		return errors.New("frame payload too large")
	}
	var head [3]byte
	head[0] = kind
	binary.BigEndian.PutUint16(head[1:], uint16(len(payload)))
	if n, err := w.Write(head[:]); err != nil || n != len(head) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	if len(payload) == 0 {
		return nil // a zero-length write can block a synchronous stream forever
	}
	if n, err := w.Write(payload); err != nil || n != len(payload) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	return nil
}

// ReadFrame reads one frame, refusing an unknown type, an oversized or
// malformed payload, and a resize outside the bounds.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var head [3]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(head[1:]))
	if n > MaxData {
		return 0, nil, errors.New("frame payload too large")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	switch head[0] {
	case Data:
	case Close:
		if n != 0 {
			return 0, nil, errors.New("a close frame carries nothing")
		}
	case Resize:
		if n != 4 {
			return 0, nil, errors.New("a resize frame carries columns and rows")
		}
		cols, rows := binary.BigEndian.Uint16(payload), binary.BigEndian.Uint16(payload[2:])
		if cols < 1 || cols > MaxCols || rows < 1 || rows > MaxRows {
			return 0, nil, fmt.Errorf("window size %dx%d is out of bounds", cols, rows)
		}
	default:
		return 0, nil, fmt.Errorf("unknown frame type %q", head[0])
	}
	return head[0], payload, nil
}

// ResizePayload encodes a window size.
func ResizePayload(cols, rows uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, cols)
	binary.BigEndian.PutUint16(b[2:], rows)
	return b
}

// ProtocolV2 is the session host's stream (POMAR-CC SOW 27 §3.2): the same
// frames as v1, plus Notice, carrying the exact screen on attach and then
// the session's live output. v1 streams never carry a Notice, and ReadFrame
// keeps refusing one.
const ProtocolV2 = "pomar-terminal/v2"

// Notice is a v2 frame from the session host to a client: a short line of
// text about the session (control taken, output resumed after a gap, the
// program exited), never terminal bytes.
const Notice byte = 'n'

// MaxNotice bounds a notice's text.
const MaxNotice = 512

// ReadFrameV2 reads one v2 frame: a v1 frame, or a bounded notice.
func ReadFrameV2(r io.Reader) (byte, []byte, error) {
	var head [3]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	if head[0] != Notice {
		return ReadFrame(io.MultiReader(bytes.NewReader(head[:]), r))
	}
	n := int(binary.BigEndian.Uint16(head[1:]))
	if n > MaxNotice {
		return 0, nil, errors.New("notice too long")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return Notice, payload, nil
}
