package eventmodel

import (
	"strings"
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

func TestDelegationValidation(t *testing.T) {
	valid := mk(KindDelegation, "", nostr.Tag{"p", strings.Repeat("a", 64)}, nostr.Tag{"server", strings.Repeat("b", 64)}, nostr.Tag{"expiry", "9999999999"}, nostr.Tag{"scope", "apps.read"})
	if err := Validate(valid); err != nil {
		t.Fatalf("valid delegation rejected: %v", err)
	}
	invalid := mk(KindDelegationRevocation, "", nostr.Tag{"e", "not-an-id"})
	if err := Validate(invalid); err == nil {
		t.Fatal("delegation revocation with invalid e tag accepted")
	}
}

func TestDelegationsAreRetainedForReplay(t *testing.T) {
	if got := Class(KindDelegation); got != ClassImmutable {
		t.Fatalf("delegation retention class = %q, want %q", got, ClassImmutable)
	}
	if got := Class(KindDelegationRevocation); got != ClassImmutable {
		t.Fatalf("delegation revocation retention class = %q, want %q", got, ClassImmutable)
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

func TestIdentityDefinitionValidation(t *testing.T) {
	pk := "84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240"
	valid := mk(KindIdentityDefinition, `{"username":"matt","signer_type":"nip46","label":"phone","enabled":true}`,
		nostr.Tag{"d", pk})
	if err := Validate(valid); err != nil {
		t.Fatalf("valid identity definition rejected: %v", err)
	}

	// missing username
	noUser := mk(KindIdentityDefinition, `{"signer_type":"nip46"}`, nostr.Tag{"d", pk})
	if err := Validate(noUser); err == nil {
		t.Fatal("identity without username should be rejected")
	}

	// bad signer_type
	badSigner := mk(KindIdentityDefinition, `{"username":"matt","signer_type":"fido"}`, nostr.Tag{"d", pk})
	if err := Validate(badSigner); err == nil {
		t.Fatal("identity with bad signer_type should be rejected")
	}

	// bad d tag
	badD := mk(KindIdentityDefinition, `{"username":"matt"}`, nostr.Tag{"d", "nope"})
	if err := Validate(badD); err == nil {
		t.Fatal("identity with invalid d should be rejected")
	}

	// revocation (enabled:false) is valid
	revoked := mk(KindIdentityDefinition, `{"username":"matt","enabled":false}`, nostr.Tag{"d", pk})
	if err := Validate(revoked); err != nil {
		t.Fatalf("revocation form rejected: %v", err)
	}

	// revocation without a username (fork's revoke_identity form) is valid
	revokedNoUser := mk(KindIdentityDefinition, `{"username":"","enabled":false}`, nostr.Tag{"d", pk})
	if err := Validate(revokedNoUser); err != nil {
		t.Fatalf("revocation without username rejected: %v", err)
	}
}

func TestNoticeValidation(t *testing.T) {
	empty := mk(KindSystemEvent, "")
	if err := Validate(empty); err != nil {
		t.Fatalf("empty notice content should be valid: %v", err)
	}

	valid := mk(KindBackupEvent, `{"class":"backup","severity":"warning","summary":"backup skipped, disk low"}`)
	if err := Validate(valid); err != nil {
		t.Fatalf("valid notice rejected: %v", err)
	}

	badSeverity := mk(KindSecurityEvent, `{"severity":"urgent"}`)
	if err := Validate(badSeverity); err == nil {
		t.Fatal("notice with unknown severity should be rejected")
	}

	noConvention := mk(KindServiceEvent, `{"anything":"goes"}`)
	if err := Validate(noConvention); err != nil {
		t.Fatalf("notice without the class/severity convention should still be valid JSON: %v", err)
	}

	badJSON := mk(KindSystemEvent, `not json`)
	if err := Validate(badJSON); err == nil {
		t.Fatal("notice with invalid JSON should be rejected")
	}
}

func TestNoticeAccessor(t *testing.T) {
	e := mk(KindBackupEvent, `{"class":"backup","severity":"critical","summary":"restic snapshot failed"}`)
	class, severity, summary, ok := Notice(e)
	if !ok || class != "backup" || severity != SeverityCritical || summary != "restic snapshot failed" {
		t.Fatalf("Notice() = (%q, %q, %q, %v), want (backup, critical, restic snapshot failed, true)", class, severity, summary, ok)
	}

	empty := mk(KindSystemEvent, "")
	if _, _, _, ok := Notice(empty); ok {
		t.Fatal("Notice() on empty content should report ok=false")
	}

	notObject := mk(KindSystemEvent, `[1,2,3]`)
	if _, _, _, ok := Notice(notObject); ok {
		t.Fatal("Notice() on a non-object JSON body should report ok=false")
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
