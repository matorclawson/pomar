// Command pomar-shim runs inside a guest. It listens on one loopback port and
// forwards each connection, unchanged, to one Unix socket that the helper
// relays from the host over vsock. Tools in the guest reach the host's Go
// module proxy at http://127.0.0.1:<port> with no network interface.
//
// It is built static for linux/arm64 and copied into the guest like the
// source. It refuses to listen on anything but a loopback address.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:7070", "loopback address to listen on")
	socket := flag.String("socket", "/run/pomar/goproxy.sock", "Unix socket to forward to")
	ready := flag.String("ready", "", "file to create once listening")
	artifact := flag.String("artifact-export", "", "export one fixed job output as bounded framed bytes")
	maximum := flag.Int64("artifact-max", 0, "protected per-file ceiling")
	seconds := flag.Int64("artifact-timeout-s", 0, "remaining protected transfer deadline")
	flag.Parse()
	artifactMode := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "artifact-export" || f.Name == "artifact-max" || f.Name == "artifact-timeout-s" {
			artifactMode = true
		}
	})
	if artifactMode {
		mixed := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "listen" || f.Name == "socket" || f.Name == "ready" {
				mixed = true
			}
		})
		if flag.NArg() != 0 || mixed || !artifactName.MatchString(*artifact) || *maximum <= 0 || *maximum > 1<<30 || *seconds <= 0 || *seconds > 600 || os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "pomar-shim: invalid protected artifact export")
			os.Exit(2)
		}
		timer := time.AfterFunc(time.Duration(*seconds)*time.Second, func() { os.Exit(124) })
		defer timer.Stop()
		directory := "/pomar/outputs/.pomar-stage"
		before, err := os.Lstat(directory)
		if err != nil || !before.IsDir() {
			fmt.Fprintln(os.Stderr, "pomar-shim: artifact stage unavailable")
			os.Exit(1)
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pomar-shim: artifact stage unavailable")
			os.Exit(1)
		}
		defer root.Close()
		fd, err := root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pomar-shim: artifact stage unavailable")
			os.Exit(1)
		}
		opened, err := fd.Stat()
		fd.Close()
		if err != nil || !os.SameFile(before, opened) {
			fmt.Fprintln(os.Stderr, "pomar-shim: artifact stage changed")
			os.Exit(1)
		}
		if err = exportArtifact(root, *artifact, *maximum, 1000, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "pomar-shim: artifact export refused")
			os.Exit(1)
		}
		return
	}
	if err := run(*listen, *socket, *ready); err != nil {
		fmt.Fprintln(os.Stderr, "pomar-shim:", err)
		os.Exit(1)
	}
}

// checkLoopback requires a loopback IP and a decimal port in 0..65535.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not a loopback IP", addr)
	}
	if len(port) == 0 || len(port) > 5 {
		return fmt.Errorf("listen port must be an ASCII decimal number in 0..65535")
	}
	value := 0
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return fmt.Errorf("listen port must be an ASCII decimal number in 0..65535")
		}
		value = value*10 + int(port[i]-'0')
	}
	if value > 65535 {
		return fmt.Errorf("listen port must be an ASCII decimal number in 0..65535")
	}
	return nil
}

func run(listen, socket, ready string) error {
	if err := checkLoopback(listen); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	if ready != "" {
		if err := os.WriteFile(ready, nil, 0o644); err != nil {
			return err
		}
	}
	return serve(ln, socket)
}

func serve(ln net.Listener, socket string) error {
	for {
		c, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		go forward(c, socket)
	}
}

func forward(c net.Conn, socket string) {
	defer c.Close()
	u, err := net.Dial("unix", socket)
	if err != nil {
		return
	}
	defer u.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(u, c); closeWrite(u) }()
	go func() { defer wg.Done(); io.Copy(c, u); closeWrite(c) }()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
