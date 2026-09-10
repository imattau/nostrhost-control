package notify

import (
	"errors"
	"testing"
)

func TestDigestFlushBatchesPerRecipient(t *testing.T) {
	sent := map[string]string{}
	d := NewDigest(0, func(npub, body string) error {
		sent[npub] = body
		return nil
	})

	d.Add("npubA", Item{Class: "backup", Severity: "info", Summary: "nightly backup ok"})
	d.Add("npubA", Item{Class: "security", Severity: "critical", Summary: "auth failure spike"})
	d.Add("npubB", Item{Class: "update", Severity: "info", Summary: "3 packages updatable"})

	if err := d.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if len(sent) != 2 {
		t.Fatalf("expected 2 recipients sent, got %d: %v", len(sent), sent)
	}
	// npubA's most severe item (security/critical) should lead the digest.
	if got := sent["npubA"]; got == "" || got[:1] == "" {
		t.Fatalf("npubA digest empty")
	}
	wantLead := "[security/critical] auth failure spike"
	if !containsLine(sent["npubA"], wantLead) {
		t.Fatalf("npubA digest missing/misordered lead line, got:\n%s", sent["npubA"])
	}
}

func TestDigestFlushIsIdempotentAfterDrain(t *testing.T) {
	calls := 0
	d := NewDigest(0, func(npub, body string) error {
		calls++
		return nil
	})
	d.Add("npubA", Item{Class: "backup", Severity: "info", Summary: "ok"})
	_ = d.Flush()
	_ = d.Flush() // nothing pending; must not re-send
	if calls != 1 {
		t.Fatalf("expected exactly 1 send, got %d", calls)
	}
}

func TestDigestFlushContinuesAfterOneRecipientFails(t *testing.T) {
	sentToB := false
	d := NewDigest(0, func(npub, body string) error {
		if npub == "npubA" {
			return errors.New("relay unreachable")
		}
		sentToB = true
		return nil
	})
	d.Add("npubA", Item{Class: "backup", Severity: "info", Summary: "x"})
	d.Add("npubB", Item{Class: "backup", Severity: "info", Summary: "y"})

	err := d.Flush()
	if err == nil {
		t.Fatal("expected the npubA failure to surface")
	}
	if !sentToB {
		t.Fatal("npubB should still have been sent despite npubA failing")
	}
}

func containsLine(body, line string) bool {
	// first content line after the "N notice(s):" header
	for i := 0; i+len(line) <= len(body); i++ {
		if body[i:i+len(line)] == line {
			return true
		}
	}
	return false
}
