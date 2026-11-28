package venue

import (
	"syscall"
	"testing"
)

func TestLinuxSpaceAccounting(t *testing.T) {
	for _, tc := range []struct {
		name            string
		useFragmentSize bool
		used, avail     int64
	}{
		{"fragment size", true, 40 * 1024, 55 * 1024},
		{"block-size fallback", false, 40 * 4096, 55 * 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			v, err := OpenWithOptions(root, Options{Statfs: func(path string, s *syscall.Statfs_t) error {
				if path != root {
					t.Fatalf("queried %q, want only %q", path, root)
				}
				s.Bsize = 4096
				s.Frsize = 0
				if tc.useFragmentSize {
					s.Frsize = 1024
				}
				s.Blocks, s.Bfree, s.Bavail = 100, 60, 55
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := v.Space()
			want := Space{Used: tc.used, Avail: tc.avail, Shared: true}
			if err != nil || got != want {
				t.Fatalf("Space() = %+v, %v; want %+v", got, err, want)
			}
		})
	}
}
