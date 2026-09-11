package notify

import (
	"context"
	"log"
	"time"

	"github.com/imattau/nostrhost-control/internal/eventmodel"
	"github.com/nbd-wtf/go-nostr"
)

// SubscribedKinds are the control-plane kinds the notification service
// reacts to. See docs/NOTIFICATION-SERVICE.md (umbrella repo) §3.
func SubscribedKinds() []int {
	return []int{
		eventmodel.KindOperationRequest,
		eventmodel.KindExecutionResult,
		eventmodel.KindSystemEvent,
		eventmodel.KindServiceEvent,
		eventmodel.KindBackupEvent,
		eventmodel.KindSecurityEvent,
	}
}

// Service wires policy matching, immediate delivery and digest batching
// together. It holds no control-plane authority of its own: it only reads
// events it's allowed to read (system/service/backup/security notices and
// the operation chain, all world-readable on the loopback relay) and writes
// to relays outside the control plane (the notifier's own DM relays).
type Service struct {
	Policy Policy
	Sender Sender
	Digest *Digest
}

// NewService builds a Service. digestInterval and sender come from the
// caller (main.go) so tests can inject a fake Sender.
func NewService(policy Policy, sender Sender) *Service {
	svc := &Service{Policy: policy, Sender: sender}
	svc.Digest = NewDigest(0, svc.sendDigest)
	return svc
}

// HandleEvent classifies event and, for each matching rule, either sends an
// immediate DM or queues it for the next digest flush. Errors are logged,
// not returned — one bad delivery must not stop the subscription loop.
func (s *Service) HandleEvent(ctx context.Context, event *nostr.Event) {
	item, ok := Classify(event)
	if !ok {
		return
	}
	for _, rule := range s.Policy.Match(item.Class, item.Severity) {
		switch rule.DeliveryMode {
		case DeliveryImmediate:
			pk, ok := s.Policy.RecipientPubkey(rule.Recipient)
			if !ok {
				continue
			}
			start := time.Now()
			if err := s.Sender.Send(ctx, pk, FormatImmediate(item), rule.Scope); err != nil {
				log.Printf("notify: immediate send to %s failed after %s: %v", rule.Recipient, time.Since(start), err)
			}
		case DeliverySummary:
			s.Digest.Add(rule.Recipient, item)
		}
	}
}

func (s *Service) sendDigest(recipientNpub, body string) error {
	pk, ok := s.Policy.RecipientPubkey(recipientNpub)
	if !ok {
		return nil // recipient removed from policy between queueing and flush
	}
	// Digest delivery uses whatever scope the recipient's rules request;
	// since a recipient may have multiple summary rules with different
	// scopes, default to the safer ScopeLocalOnly for the combined digest.
	return s.Sender.Send(context.Background(), pk, body, ScopeLocalOnly)
}

// Filter returns the subscription filter for the local control-plane relay.
func Filter() nostr.Filter {
	return nostr.Filter{Kinds: SubscribedKinds()}
}
