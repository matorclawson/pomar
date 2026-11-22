// Command pomar-agent-host serves development agent environments independently
// of the permanent Pomar CI manager.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rodriveracom/pomar/integrations/zeo/seatapi"
	"github.com/rodriveracom/pomar/integrations/zeo/seatdecl"
	"github.com/rodriveracom/pomar/integrations/zeomessenger"
	"github.com/rodriveracom/pomar/internal/agentenv"
)

func main() {
	file := flag.String("config", "", "owner-supplied development configuration")
	flag.Parse()
	config, err := agentenv.ReadHostConfig(*file)
	if err == nil && config.SeatHere != "" && (config.SeatRoot == "" || !seatdecl.ValidWhere(config.SeatHere)) {
		err = fmt.Errorf("seatHere %q needs a seatRoot and a location name such as pomar:macbook", config.SeatHere)
	}
	if err == nil {
		var host *agentenv.Host
		host, err = agentenv.OpenHostWithChannel(config, zeomessenger.OpenChannel)
		if err == nil {
			defer host.Close()
			if config.SeatRoot != "" {
				seats := seatapi.Store{Root: config.SeatRoot, Here: config.SeatHere}.Handler()
				host.Mount("/v1/seats", seats)
				host.Mount("/v1/seats/", seats)
			}
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			err = host.Serve(ctx)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pomar-agent-host:", err)
		os.Exit(1)
	}
}
