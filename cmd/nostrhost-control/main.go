// nostrhost-control is the NostrHost control-plane service: a local,
// loopback-only Nostr relay with event-model validation, NIP-42 auth, NIP-86
// management, per-kind retention and NIP-77 sync, built on khatru.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/imattau/nostrhost-control/internal/config"
	"github.com/imattau/nostrhost-control/internal/relay"
)

func main() {
	cfgPath := flag.String("config", "config.toml", "path to the control-plane config (TOML)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("nostrhost-control: %v", err)
	}

	srv, err := relay.New(cfg)
	if err != nil {
		log.Fatalf("nostrhost-control: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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
