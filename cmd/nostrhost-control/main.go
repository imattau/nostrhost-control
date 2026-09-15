// nostrhost-control is the NostrHost control-plane service: a local,
// loopback-only Nostr relay with event-model validation, NIP-42 auth, NIP-86
// management, per-kind retention and NIP-77 sync, built on khatru.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/imattau/nostrhost-control/internal/cmdutil"
	"github.com/imattau/nostrhost-control/internal/config"
	"github.com/imattau/nostrhost-control/internal/relay"
)

func main() {
	cfgPath := flag.String("config", "config.toml", "path to the control-plane config (TOML)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	cmdutil.FatalIfErr("nostrhost-control", err)

	srv, err := relay.New(cfg)
	cmdutil.FatalIfErr("nostrhost-control", err)

	ctx, stop := cmdutil.SignalContext()
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- srv.Start() }()

	select {
	case err := <-errc:
		if err != nil {
			log.Fatalf("nostrhost-control: %v", err)
		}
	case <-ctx.Done():
		log.Println("nostrhost-control: shutting down")
		srv.Shutdown(context.Background())
	}
}
