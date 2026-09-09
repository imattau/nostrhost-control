package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip86"

	"github.com/imattau/nostrhost-control/internal/config"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startServer(t *testing.T, operatorPubkey string, mutate func(*config.Config)) (*Server, string) {
	t.Helper()
	cfg := config.Default()
	cfg.ListenHost = "127.0.0.1"
	cfg.ListenPort = freePort(t)
	cfg.OperatorPubkey = operatorPubkey
	cfg.EventsDBPath = filepath.Join(t.TempDir(), "events.db")
	cfg.PolicyDBPath = filepath.Join(t.TempDir(), "policy.db")
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
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
	return srv, fmt.Sprintf("127.0.0.1:%d", cfg.ListenPort)
}

func newKeys(t *testing.T) (sk, pk string) {
	t.Helper()
	sk = nostr.GeneratePrivateKey()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	return sk, pk
}

func signEvent(t *testing.T, sk string, e *nostr.Event) {
	t.Helper()
	if err := e.Sign(sk); err != nil {
		t.Fatal(err)
	}
}

func httpURL(addr string) string { return "http://" + addr }

func wsURL(addr string) string { return "ws://" + addr }

func TestNIP11AndBasicPublish(t *testing.T) {
	_, pk := newKeys(t)
	srv, addr := startServer(t, pk, nil)

	req, _ := http.NewRequest("GET", httpURL(addr)+"/", nil)
	req.Header.Set("Accept", "application/nostr+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("nip11: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("nip11 status %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["software"] != Software {
		t.Fatalf("unexpected software: %v", doc["software"])
	}

	sk, pkA := newKeys(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := nostr.RelayConnect(ctx, wsURL(addr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	evt := nostr.Event{PubKey: pkA, Kind: 1, Content: "hello", CreatedAt: nostr.Now()}
	signEvent(t, sk, &evt)
	if err := client.Publish(ctx, evt); err != nil {
		t.Fatalf("publish kind 1: %v", err)
	}

	got, err := client.QuerySync(ctx, nostr.Filter{Kinds: []int{1}, Authors: []string{pkA}})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 || got[0].Content != "hello" {
		t.Fatalf("unexpected query result: %+v", got)
	}

	if srv.Policy.IsAdmin(pk) == false {
		t.Fatal("operator should be an admin")
	}
}

func TestNIP42AuthRequiredForControlKinds(t *testing.T) {
	_, pk := newKeys(t)
	_, addr := startServer(t, pk, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// unauthenticated client cannot write a control kind
	skB, pkB := newKeys(t)
	client, err := nostr.RelayConnect(ctx, wsURL(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	reqEvt := nostr.Event{PubKey: pkB, Kind: 2200, Content: `{"tool":"app.upgrade","args":{"id":"ditto"}}`, CreatedAt: nostr.Now()}
	signEvent(t, skB, &reqEvt)
	if err := client.Publish(ctx, reqEvt); err == nil || !strings.Contains(err.Error(), "authentication required") {
		t.Fatalf("expected auth-required, got: %v", err)
	}

	// operator authenticates via NIP-42 and can then write the control kind
	skA, pkA := newKeys(t)
	authed, err := nostr.RelayConnect(ctx, wsURL(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer authed.Close()

	reqEvt2 := nostr.Event{PubKey: pkA, Kind: 2200, Content: `{"tool":"app.upgrade","args":{"id":"ditto"}}`, CreatedAt: nostr.Now()}
	signEvent(t, skA, &reqEvt2)

	// First publish triggers the relay's NIP-42 challenge (and is rejected);
	// the challenge lets the client complete AUTH. Retry a couple times in
	// case the challenge delivery races the OK.
	authedOk := false
	for attempt := 0; attempt < 3 && !authedOk; attempt++ {
		err = authed.Publish(ctx, reqEvt2)
		if err == nil {
			authedOk = true
			break
		}
		if !strings.Contains(err.Error(), "authentication required") {
			t.Fatalf("unexpected publish error: %v", err)
		}
		if aerr := authed.Auth(ctx, func(e *nostr.Event) error { return e.Sign(skA) }); aerr != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if err = authed.Publish(ctx, reqEvt2); err == nil {
			authedOk = true
		}
	}
	if !authedOk {
		t.Fatalf("authenticated publish never succeeded: %v", err)
	}
}

func TestNIP86BanPubkey(t *testing.T) {
	sk, pk := newKeys(t)
	_, addr := startServer(t, pk, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	skB, pkB := newKeys(t)
	client, err := nostr.RelayConnect(ctx, wsURL(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// initially pkB can publish kind 1
	evt := nostr.Event{PubKey: pkB, Kind: 1, Content: "x", CreatedAt: nostr.Now()}
	signEvent(t, skB, &evt)
	if err := client.Publish(ctx, evt); err != nil {
		t.Fatalf("publish before ban: %v", err)
	}

	// ban pkB via NIP-86 as operator
	if err := nip86Call(t, sk, addr, "banpubkey", []string{pkB}); err != nil {
		t.Fatalf("banpubkey: %v", err)
	}

	// now pkB's publish is rejected
	evt2 := nostr.Event{PubKey: pkB, Kind: 1, Content: "y", CreatedAt: nostr.Now()}
	signEvent(t, skB, &evt2)
	if err := client.Publish(ctx, evt2); err == nil || !strings.Contains(err.Error(), "banned") {
		t.Fatalf("expected ban rejection, got: %v", err)
	}

	// list banned
	if err := nip86Call(t, sk, addr, "listbannedpubkeys", nil); err != nil {
		t.Fatalf("listbannedpubkeys: %v", err)
	}
}

func TestNIP86AllowKind(t *testing.T) {
	sk, pk := newKeys(t)
	_, addr := startServer(t, pk, func(c *config.Config) {
		c.AllowedKinds = []int{1}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	skA, pkA := newKeys(t)
	client, err := nostr.RelayConnect(ctx, wsURL(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	evt := nostr.Event{PubKey: pkA, Kind: 7, Content: "no", CreatedAt: nostr.Now()}
	signEvent(t, skA, &evt)
	if err := client.Publish(ctx, evt); err == nil || !strings.Contains(err.Error(), "kind not allowed") {
		t.Fatalf("expected kind-not-allowed, got: %v", err)
	}

	// allow kind 2 via NIP-86, then publish succeeds
	if err := nip86Call(t, sk, addr, "allowkind", []int{7}); err != nil {
		t.Fatalf("allowkind: %v", err)
	}
	if err := client.Publish(ctx, evt); err != nil {
		t.Fatalf("publish after allowkind: %v", err)
	}
}

// nip86Call issues a NIP-86 JSON-RPC request authenticated with a NIP-98
// header signed by adminSk. params is JSON-marshaled as the params array.
func nip86Call(t *testing.T, adminSk, addr, method string, params any) error {
	t.Helper()
	adminPk, err := nostr.GetPublicKey(adminSk)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"method": method, "params": params})
	if err != nil {
		return err
	}
	url := httpURL(addr) + "/"
	sum := sha256.Sum256(body)

	authEvt := nostr.Event{
		PubKey:    adminPk,
		Kind:      27235,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"u", url},
			{"method", "POST"},
			{"payload", hex.EncodeToString(sum[:])},
		},
	}
	signEvent(t, adminSk, &authEvt)
	authJSON, _ := json.Marshal(authEvt)
	authHeader := "Nostr " + base64.StdEncoding.EncodeToString(authJSON)

	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/nostr+json+rpc")
	req.Header.Set("Authorization", authHeader)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out nip86.Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Error != "" {
		return fmt.Errorf("nip86 %s: %s", method, out.Error)
	}
	return nil
}

func TestProtectedKindsSemantics(t *testing.T) {
	cfg := config.Default()
	cfg.OperatorPubkey = mustPubkey(t)
	cfg.EventsDBPath = filepath.Join(t.TempDir(), "events.db")
	cfg.PolicyDBPath = filepath.Join(t.TempDir(), "policy.db")
	cfg.RequireAuthKinds = nil
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.protectedKinds(); len(got) == 0 {
		t.Fatal("nil require_auth_kinds should use the default protected set")
	}
	_ = srv.Policy.Close() // release the bolt lock before reopening the path

	cfg.RequireAuthKinds = []int{}
	srv2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := srv2.protectedKinds(); len(got) != 0 {
		t.Fatalf("empty require_auth_kinds should disable NIP-42, got %v", got)
	}
}

func mustPubkey(t *testing.T) string {
	t.Helper()
	return "84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240"
}
