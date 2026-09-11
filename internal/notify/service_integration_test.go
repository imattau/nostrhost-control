package notify

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imattau/nostrhost-control/internal/config"
	"github.com/imattau/nostrhost-control/internal/eventmodel"
	"github.com/imattau/nostrhost-control/internal/relay"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/keyer"
)

func wsURL(addr string) string { return "ws://" + addr }

func startRelay(t *testing.T, operatorPk string) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := config.Default()
	cfg.ListenHost = "127.0.0.1"
	cfg.ListenPort = port
	cfg.OperatorPubkey = operatorPk
	cfg.EventsDBPath = filepath.Join(t.TempDir(), "events.db")
	cfg.PolicyDBPath = filepath.Join(t.TempDir(), "policy.db")

	srv, err := relay.New(cfg)
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	started := make(chan bool)
	go func() { _ = srv.Start(started) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// publishAuthed retries publishing a protected-kind event, completing the
// relay's NIP-42 challenge with the signer key the same way the relay's own
// tests do.
func publishAuthed(t *testing.T, ctx context.Context, addr, sk string, ev *nostr.Event) {
	t.Helper()
	if err := ev.Sign(sk); err != nil {
		t.Fatal(err)
	}
	rel, err := nostr.RelayConnect(ctx, wsURL(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer rel.Close()
	for attempt := 0; attempt < 3; attempt++ {
		err = rel.Publish(ctx, *ev)
		if err == nil {
			return
		}
		if !strings.Contains(err.Error(), "authentication required") {
			t.Fatalf("unexpected publish error: %v", err)
		}
		if aerr := rel.Auth(ctx, func(e *nostr.Event) error { return e.Sign(sk) }); aerr != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if err = rel.Publish(ctx, *ev); err == nil {
			return
		}
	}
	t.Fatalf("authenticated publish never succeeded: %v", err)
}

// TestAuthenticatedSubscriptionReceivesProtectedNotice proves the notify
// service's subscription wiring (a pool with a NIP-42 WithAuthHandler using
// the notifier key) can read a protected kind (2213) from the control-plane
// relay with the default ProtectedKinds posture — i.e. that the same pool
// construction main.go uses works against a real relay.
func TestAuthenticatedSubscriptionReceivesProtectedNotice(t *testing.T) {
	operatorSk, operatorPk := nostr.GeneratePrivateKey(), ""
	var err error
	if operatorPk, err = nostr.GetPublicKey(operatorSk); err != nil {
		t.Fatal(err)
	}
	addr := startRelay(t, operatorPk)

	notifierSk := nostr.GeneratePrivateKey()
	kr, err := keyer.NewPlainKeySigner(notifierSk)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool := nostr.NewSimplePool(ctx, nostr.WithAuthHandler(func(ctx context.Context, ev nostr.RelayEvent) error {
		return kr.SignEvent(ctx, ev.Event)
	}))

	got := make(chan *nostr.Event, 1)
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	go func() {
		for ie := range pool.SubscribeMany(subCtx, []string{wsURL(addr)}, nostr.Filter{Kinds: []int{eventmodel.KindSecurityEvent}}) {
			select {
			case got <- ie.Event:
			default:
			}
		}
	}()

	// Give the subscription a moment to establish, then publish a protected
	// kind-2213 notice as the operator (writing it also needs NIP-42 auth).
	time.Sleep(500 * time.Millisecond)
	ev := &nostr.Event{
		Kind:      eventmodel.KindSecurityEvent,
		Content:   `{"class":"security","severity":"warning","summary":"intrusion detected from 1.2.3.4","source":"1.2.3.4"}`,
		PubKey:    operatorPk,
		CreatedAt: nostr.Now(),
	}
	publishAuthed(t, ctx, addr, operatorSk, ev)

	select {
	case e := <-got:
		item, ok := Classify(e)
		if !ok {
			t.Fatal("classify: unexpected skip")
		}
		if item.Class != "security" || item.Summary != "intrusion detected from 1.2.3.4" {
			t.Fatalf("unexpected item: %+v", item)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive protected 2213 via authenticated subscription")
	}
}