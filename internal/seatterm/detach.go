package seatterm

import "io"

// DetachReader implements the operator's local Ctrl-b d chord. It never sends
// the detach chord to the actor. Ctrl-b Ctrl-b sends one literal Ctrl-b; other
// prefixed bytes pass through unchanged. Use only for interactive attachment.
type DetachReader struct {
	Input        io.Reader
	prefix, done bool
	pending      []byte
	endError     error
}

func (r *DetachReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	if r.done {
		if r.endError != nil {
			return 0, r.endError
		}
		return 0, io.EOF
	}
	buf := make([]byte, min(len(p), 4096))
	n, e := r.Input.Read(buf)
	for _, b := range buf[:n] {
		if r.prefix {
			r.prefix = false
			if b == 'd' {
				r.done = true
				break
			}
			r.pending = append(r.pending, 2)
			if b == 2 {
				continue
			}
		} else if b == 2 {
			r.prefix = true
			continue
		}
		r.pending = append(r.pending, b)
	}
	if e != nil && !r.done {
		r.endError = e
		if r.prefix {
			r.pending = append(r.pending, 2)
			r.prefix = false
		}
		r.done = true
	}
	count := copy(p, r.pending)
	r.pending = r.pending[count:]
	if count > 0 {
		return count, nil
	}
	if r.done {
		if r.endError != nil {
			return 0, r.endError
		}
		return 0, io.EOF
	}
	return 0, nil
}
