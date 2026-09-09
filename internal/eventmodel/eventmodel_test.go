package eventmodel

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func mk(kind int, content string, tags ...nostr.Tag) *nostr.Event {
	return &nostr.Event{Kind: kind, Content: content, Tags: tags}
}

func TestValidateNonCustomKindPasses(t *testing.T) {
	e := mk(1, "hello")
	if err := Validate(e); err != nil {
		t.Fatalf("kind 1 should pass: %v", err)
	}
}

func TestCapabilityValidation(t *testing.T) {
	valid := mk(KindCapability, `{"type":"admin","scopes":["app.install","backup.create"]}`,
		nostr.Tag{"d", "84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240"})
	if err := Validate(valid); err != nil {
		t.Fatalf("valid capability rejected: %v", err)
	}

	badD := mk(KindCapability, `{"type":"admin"}`, nostr.Tag{"d", "not-a-pubkey"})
	if err := Validate(badD); err == nil {
		t.Fatal("capability with invalid d should be rejected")
	}

	noType := mk(KindCapability, `{}`, nostr.Tag{"d", "84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240"})
	if err := Validate(noType); err == nil {
		t.Fatal("capability without type should be rejected")
	}

	noD := mk(KindCapability, `{"type":"admin"}`)
	if err := Validate(noD); err == nil {
		t.Fatal("capability without d should be rejected")
	}
}

func TestOperationChainValidation(t *testing.T) {
	req := mk(KindOperationRequest, `{"tool":"app.upgrade","args":{"id":"ditto"}}`)
	if err := Validate(req); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	noTool := mk(KindOperationRequest, `{"args":{}}`)
	if err := Validate(noTool); err == nil {
		t.Fatal("request without tool should be rejected")
	}

	badJSON := mk(KindOperationRequest, `not json`)
	if err := Validate(badJSON); err == nil {
		t.Fatal("request with bad JSON should be rejected")
	}

	// chain steps must reference the request
	approval := mk(KindOperationApproval, `{}`, nostr.Tag{"e", "9d24ddfab95ba3ff7c03fbd07ad011fff245abea431fb4d3787c2d04aad02332"})
	if err := Validate(approval); err != nil {
		t.Fatalf("valid approval rejected: %v", err)
	}

	orphan := mk(KindExecutionResult, `{"ok":true}`)
	if err := Validate(orphan); err == nil {
		t.Fatal("chain step without e tag should be rejected")
	}
}

func TestRetentionClasses(t *testing.T) {
	cases := map[int]string{
		KindOperationRequest: ClassImmutable,
		KindCapability:       ClassReplaceable,
		20001:                ClassEphemeral,
		10002:                ClassReplaceable,
		1000:                 ClassImmutable,
	}
	for kind, want := range cases {
		if got := Class(kind); got != want {
			t.Errorf("Class(%d) = %q, want %q", kind, got, want)
		}
	}
}
