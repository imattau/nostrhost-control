package notify

import (
	"context"
	"testing"

	"github.com/imattau/nostrhost-control/internal/eventmodel"
	"github.com/nbd-wtf/go-nostr"
)

type fakeSend struct {
	pubkey string
	body   string
	scope  Scope
}

type fakeSender struct {
	sends []fakeSend
	err   error
}

func (f *fakeSender) Send(ctx context.Context, pubkey, body string, scope Scope) error {
	f.sends = append(f.sends, fakeSend{pubkey, body, scope})
	return f.err
}

func testPolicy(t *testing.T, policyBody string) Policy {
	t.Helper()
	dir := t.TempDir()
	recipients := writeTemp(t, dir, "recipients.toml", `
[[recipient]]
npub = "`+testNpub+`"
role = "owner"
`)
	rules := writeTemp(t, dir, "policy.toml", policyBody)
	p, err := LoadPolicy(recipients, rules)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return p
}

func TestServiceHandleEventImmediate(t *testing.T) {
	p := testPolicy(t, `
[[rule]]
recipient = "`+testNpub+`"
classes = ["security"]
severity_min = "warning"
delivery = "immediate"
scope = "local-only"
`)
	sender := &fakeSender{}
	svc := NewService(p, sender)

	svc.HandleEvent(context.Background(), &nostr.Event{Kind: eventmodel.KindSecurityEvent, Content: ""})

	if len(sender.sends) != 1 {
		t.Fatalf("expected 1 immediate send, got %d", len(sender.sends))
	}
	pk, _ := p.RecipientPubkey(testNpub)
	if sender.sends[0].pubkey != pk {
		t.Errorf("sent to wrong pubkey: %s", sender.sends[0].pubkey)
	}
}

func TestServiceHandleEventBelowThresholdIsSkipped(t *testing.T) {
	p := testPolicy(t, `
[[rule]]
recipient = "`+testNpub+`"
classes = ["backup"]
severity_min = "critical"
delivery = "immediate"
scope = "local-only"
`)
	sender := &fakeSender{}
	svc := NewService(p, sender)

	// backup notices default to "info" severity, below the rule's "critical".
	svc.HandleEvent(context.Background(), &nostr.Event{Kind: eventmodel.KindBackupEvent, Content: ""})

	if len(sender.sends) != 0 {
		t.Fatalf("expected no sends below threshold, got %d", len(sender.sends))
	}
}

func TestServiceHandleEventSummaryQueuesInsteadOfSending(t *testing.T) {
	p := testPolicy(t, `
[[rule]]
recipient = "`+testNpub+`"
classes = ["backup"]
severity_min = "info"
delivery = "summary"
scope = "local-only"
`)
	sender := &fakeSender{}
	svc := NewService(p, sender)

	svc.HandleEvent(context.Background(), &nostr.Event{Kind: eventmodel.KindBackupEvent, Content: ""})
	if len(sender.sends) != 0 {
		t.Fatalf("summary delivery should not send immediately, got %d sends", len(sender.sends))
	}

	if err := svc.Digest.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(sender.sends) != 1 {
		t.Fatalf("expected 1 send after flush, got %d", len(sender.sends))
	}
}

func TestServiceHandleEventUnrelatedKindIsIgnored(t *testing.T) {
	p := testPolicy(t, `
[[rule]]
recipient = "`+testNpub+`"
classes = ["backup"]
severity_min = "info"
delivery = "immediate"
scope = "local-only"
`)
	sender := &fakeSender{}
	svc := NewService(p, sender)

	svc.HandleEvent(context.Background(), &nostr.Event{Kind: eventmodel.KindCapability, Content: "{}"})
	if len(sender.sends) != 0 {
		t.Fatalf("expected no sends for an unrelated kind, got %d", len(sender.sends))
	}
}
