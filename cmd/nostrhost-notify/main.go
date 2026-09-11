// nostrhost-notify is the native notification service (roadmap §18.1): it
// subscribes to structured system/service/backup/security notices and the
// operation chain on the local nostrhost-control relay, and delivers
// human-readable summaries to configured npubs as encrypted Nostr direct
// messages (NIP-17/NIP-59). See the umbrella repo's
// docs/NOTIFICATION-SERVICE.md for the design.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/imattau/nostrhost-control/internal/notify"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/keyer"
)

// cursor is the last-seen event cursor persisted to StatePath so restarts
// resume without re-delivering the full event history.
type cursor struct {
	LastSeen int64 `json:"last_seen"`
	path     string
}

func loadCursor(path string) (*cursor, bool, error) {
	c := &cursor{path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, false, nil
		}
		return nil, false, err
	}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, false, err
	}
	return c, true, nil
}

func (c *cursor) save() error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, raw, 0600)
}

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

	cur, hasState, err := loadCursor(cfg.StatePath)
	if err != nil {
		log.Fatalf("nostrhost-notify: cursor: %v", err)
	}
	if !hasState {
		// Fresh install: don't replay years of history into DMs. Subsequent
		// restarts resume from the persisted cursor, so no event published
		// while the service was down is lost either.
		cur.LastSeen = time.Now().Unix()
		if err := cur.save(); err != nil {
			log.Printf("nostrhost-notify: initial cursor save: %v", err)
		}
	}
	log.Printf("nostrhost-notify: resuming from last_seen=%d", cur.LastSeen)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	kr, err := keyer.NewPlainKeySigner(cfg.NotifierPrivateKey)
	if err != nil {
		log.Fatalf("nostrhost-notify: notifier key: %v", err)
	}

	// The local control-plane relay protects the notice kinds (2210-2213,
	// and the operation chain) with NIP-42 auth on read (ProtectedKinds).
	// Authenticate as the notifier itself so the subscription is accepted;
	// the notifier key has no control-plane authority, it only proves a
	// valid identity to read notices it is then allowed to deliver.
	pool := nostr.NewSimplePool(ctx, nostr.WithAuthHandler(func(ctx context.Context, ev nostr.RelayEvent) error {
		return kr.SignEvent(ctx, ev.Event)
	}))
	sender, err := notify.NewNIP17Sender(cfg, pool, kr)
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
	since := nostr.Timestamp(cur.LastSeen)
	f := notify.Filter()
	f.Since = &since
	for ie := range pool.SubscribeMany(ctx, []string{cfg.RelayURL}, f) {
		if int64(ie.Event.CreatedAt) > cur.LastSeen {
			cur.LastSeen = int64(ie.Event.CreatedAt)
			if err := cur.save(); err != nil {
				log.Printf("nostrhost-notify: cursor save: %v", err)
			}
		}
		svc.HandleEvent(ctx, ie.Event)
	}
	log.Printf("nostrhost-notify: subscription ended")
}
