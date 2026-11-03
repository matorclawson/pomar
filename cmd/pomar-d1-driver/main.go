// pomar-d1-driver provides the closed process-observation role of the
// pre-model driver. The owner must bind it to the actual guest namespace.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/prequal"
)

const observationLimit = 1 << 20

type collector func(context.Context, string) (prequal.ProcessSnapshot, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, prequal.CollectLinuxProcessSnapshot)
	stop()
	os.Exit(code)
}

func run(parent context.Context, args []string, out, diagnostic io.Writer, collect collector) int {
	if len(args) != 4 || args[0] != "-mode" || args[1] != "processes" || args[2] != "-scope" || args[3] == "" || len(args[3]) > 256 {
		fmt.Fprintln(diagnostic, "usage: pomar-d1-driver -mode processes -scope ORIGINAL; mail mode is not implemented")
		return 2
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		fmt.Fprintln(diagnostic, err)
		return 1
	}
	snapshot, err := collect(ctx, args[3])
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && (snapshot.ScopeID != args[3] || snapshot.Kind != prequal.OwnerGuestInventoryKind || len(snapshot.Rows) == 0 || len(snapshot.Rows) > 65536) {
		err = errors.New("complete original-scope process observation required")
	}
	// Refuse a large observation without emitting a partial JSON prefix. This
	// conservative preflight also bounds Marshal's additional allocation.
	if err == nil {
		size := 1024
		for _, p := range snapshot.Rows {
			size += 256 + 6*len(p.Exe)
			for _, arg := range p.Args {
				size += 4 + 6*len(arg)
				if size > observationLimit {
					break
				}
			}
			if size > observationLimit {
				err = errors.New("complete process observation exceeds output budget")
				break
			}
		}
	}
	var raw []byte
	if err == nil {
		raw, err = json.Marshal(snapshot)
		if len(raw)+1 > observationLimit {
			err = errors.New("complete process observation exceeds output budget")
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 1
	}
	raw = append(raw, '\n')
	n, err := out.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 1
	}
	return 0
}
