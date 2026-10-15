package manager

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A manager that accepts a connection and never answers must not hold a
// raw/rawBulk caller forever (zeocouncil's P1 on #128: server.go's raw,
// outputlog.go's log fetch and outputs.go's Output all used c.http.Get with
// no context, on a client with no Timeout, so none of them were actually
// bounded despite AGENTS.md's claim).
func TestRawIsBoundedAgainstAHungManager(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "pomarbulk")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hang // never answers until the test ends
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	c := NewSocketClient(sock)
	start := time.Now()
	if _, err := c.rawBound("/v1/attempts/x/result", 200*time.Millisecond); err == nil {
		t.Fatal("a hung manager was not bounded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("rawBound waited %v past its 200ms bound", d)
	}
}
