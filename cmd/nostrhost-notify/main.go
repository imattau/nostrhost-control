// nostrhost-notify is the native notification service (roadmap §18.1): it
// subscribes to structured system/service/backup/security notices and the
// operation chain on the local nostrhost-control relay, and delivers
// human-readable summaries to configured npubs as encrypted Nostr direct
// messages (NIP-17/NIP-59). See the umbrella repo's
// docs/NOTIFICATION-SERVICE.md for the design.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/imattau/nostrhost-control/internal/notify"
	"github.com/nbd-wtf/go-nostr"
)

func main() {
	cfgPath := flag.String("config", "notify.toml", "path to the notification service config (TOML)")
	flag.Parse()

	cfg, err := notify.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("nostrhost-notify: %v", err)
	}
	policy, err := notify.LoadPolicy(cfg.RecipientsPath, cfg.PolicyPath)
	if err != nil {
		log.Fatalf("nostrhost-notify: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool := nostr.NewSimplePool(ctx)
	sender, err := notify.NewNIP17Sender(cfg, pool)
	if err != nil {
		log.Fatalf("nostrhost-notify: %v", err)
	}
	svc := notify.NewService(policy, sender)

	digestInterval, err := time.ParseDuration(cfg.DigestInterval)
	if err != nil {
		log.Fatalf("nostrhost-notify: digest_interval: %v", err)
	}
	svc.Digest.Interval = digestInterval
	stopDigest := make(chan struct{})
	go svc.Digest.Run(stopDigest)
	defer close(stopDigest)

	log.Printf("nostrhost-notify: subscribing to %s", cfg.RelayURL)
	for ie := range pool.SubscribeMany(ctx, []string{cfg.RelayURL}, notify.Filter()) {
		svc.HandleEvent(ctx, ie.Event)
	}
}
