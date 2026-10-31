package seatterm

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type fragments struct{ data []byte }

func (f *fragments) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		return 0, io.EOF
	}
	p[0] = f.data[0]
	f.data = f.data[1:]
	return 1, nil
}
func TestLocalDetachChordAcrossReads(t *testing.T) {
	for _, size := range []int{1, 2, 4096} {
		r := &DetachReader{Input: &fragments{[]byte{'a', 2, 'd', 'z'}}}
		var out bytes.Buffer
		buf := make([]byte, size)
		for {
			n, e := r.Read(buf)
			out.Write(buf[:n])
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
		}
		if out.String() != "a" {
			t.Fatal(out.String())
		}
	}
}
func TestLocalDetachLiteralPrefixAndUnknownChord(t *testing.T) {
	for _, c := range []struct{ in, out []byte }{{[]byte{2, 2, 'd'}, []byte{2, 'd'}}, {[]byte{2, 'x'}, []byte{2, 'x'}}, {[]byte{'a', 2}, []byte{'a', 2}}} {
		r := &DetachReader{Input: bytes.NewReader(c.in)}
		b, e := io.ReadAll(r)
		if e != nil || !bytes.Equal(b, c.out) {
			t.Fatal(b, e)
		}
	}
}

// Deliver bytes and a non-EOF read failure together, as io.Reader permits.
type failedDetachInput struct{ data []byte }

func (r failedDetachInput) Read(p []byte) (int, error) {
	return copy(p, r.data), io.ErrUnexpectedEOF
}

func TestDetachPreservesReadFailureAfterPendingBytes(t *testing.T) {
	for _, input := range [][]byte{[]byte("ab"), {2}} {
		got, err := io.ReadAll(&DetachReader{Input: failedDetachInput{input}})
		if !bytes.Equal(got, input) || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("read failure hidden or bytes lost: %q %v", got, err)
		}
	}
}

func TestExplicitDetachTerminatesLocallyDespiteLaterInputError(t *testing.T) {
	got, err := io.ReadAll(&DetachReader{Input: failedDetachInput{[]byte{2, 'd'}}})
	if len(got) != 0 || err != nil {
		t.Fatalf("explicit local detach leaked: %q %v", got, err)
	}
}
