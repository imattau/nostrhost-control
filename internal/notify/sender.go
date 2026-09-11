package notify

import (
	"context"
	"fmt"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/keyer"
	"github.com/nbd-wtf/go-nostr/nip17"
)

// Sender delivers a notification body to a recipient (hex pubkey) as an
// encrypted Nostr direct message. It is an interface so Service can be
// tested without a live relay — NIP17Sender is the real implementation.
type Sender interface {
	Send(ctx context.Context, recipientPubkey, body string, scope Scope) error
}

// NIP17Sender delivers via NIP-17 private DMs (NIP-59 gift-wrapped), using
// go-nostr's nip17 helper. It never touches the control-plane's own
// server/operator keys — it signs with its own "notifier" key, per
// Config.NotifierPrivateKey.
type NIP17Sender struct {
	pool *nostr.SimplePool
	kr   keyer.KeySigner

	// localRelays are used for ScopeLocalOnly delivery (and as our own copy
	// for every scope) — relays explicitly configured for this purpose, not
	// the recipient's own relay list.
	localRelays []string
}

// NewNIP17Sender builds a sender from config. kr is the notifier key (also
// used by the caller to authenticate its relay subscriptions); pool may be
// shared with the subscriber (both are plain go-nostr SimplePool clients).
func NewNIP17Sender(cfg Config, pool *nostr.SimplePool, kr keyer.KeySigner) (*NIP17Sender, error) {
	if len(cfg.OutboundRelays) == 0 {
		return nil, fmt.Errorf("notify: outbound_relays must name at least one relay for notification delivery")
	}
	return &NIP17Sender{pool: pool, kr: kr, localRelays: cfg.OutboundRelays}, nil
}

// Send delivers body to recipientPubkey. ScopeLocalOnly uses only the
// configured local/outbound relay set; ScopeExternal additionally tries the
// relays the recipient's own NIP-17 DM-relay list names, falling back to the
// local set if the recipient hasn't published one.
func (s *NIP17Sender) Send(ctx context.Context, recipientPubkey, body string, scope Scope) error {
	theirRelays := s.localRelays
	if scope == ScopeExternal {
		if dm := nip17.GetDMRelays(ctx, recipientPubkey, s.pool, s.localRelays); len(dm) > 0 {
			theirRelays = dm
		}
	}
	return nip17.PublishMessage(ctx, body, nil, s.pool, s.localRelays, theirRelays, s.kr, recipientPubkey, nil)
}
