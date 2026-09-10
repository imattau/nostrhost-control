package notify

import (
	"os"
	"path/filepath"
	"testing"
)

// testNpub encodes 64 "1" hex chars — a synthetic pubkey, not a real identity.
const testNpub = "npub1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygse4sl3h"

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestLoadPolicyValid(t *testing.T) {
	dir := t.TempDir()
	recipients := writeTemp(t, dir, "recipients.toml", `
[[recipient]]
npub = "`+testNpub+`"
role = "owner"
`)
	rules := writeTemp(t, dir, "policy.toml", `
[[rule]]
recipient = "`+testNpub+`"
classes = ["security", "recovery"]
severity_min = "warning"
delivery = "immediate"
scope = "local-only"
`)

	p, err := LoadPolicy(recipients, rules)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if len(p.Recipients) != 1 || len(p.Rules) != 1 {
		t.Fatalf("unexpected policy shape: %+v", p)
	}
	pk, ok := p.RecipientPubkey(testNpub)
	if !ok || pk == "" {
		t.Fatalf("RecipientPubkey did not resolve %q", testNpub)
	}
}

func TestLoadPolicyRejectsUnknownRecipient(t *testing.T) {
	dir := t.TempDir()
	recipients := writeTemp(t, dir, "recipients.toml", "")
	rules := writeTemp(t, dir, "policy.toml", `
[[rule]]
recipient = "`+testNpub+`"
classes = ["security"]
severity_min = "info"
delivery = "immediate"
scope = "local-only"
`)
	if _, err := LoadPolicy(recipients, rules); err == nil {
		t.Fatal("expected error for rule referencing an undeclared recipient")
	}
}

func TestLoadPolicyRejectsBadNpub(t *testing.T) {
	dir := t.TempDir()
	recipients := writeTemp(t, dir, "recipients.toml", `
[[recipient]]
npub = "not-an-npub"
`)
	rules := writeTemp(t, dir, "policy.toml", "")
	if _, err := LoadPolicy(recipients, rules); err == nil {
		t.Fatal("expected error for invalid npub")
	}
}

func TestLoadPolicyRejectsBadEnum(t *testing.T) {
	dir := t.TempDir()
	recipients := writeTemp(t, dir, "recipients.toml", `
[[recipient]]
npub = "`+testNpub+`"
`)
	cases := []string{
		`[[rule]]
recipient = "` + testNpub + `"
classes = ["security"]
severity_min = "urgent"
delivery = "immediate"
scope = "local-only"`,
		`[[rule]]
recipient = "` + testNpub + `"
classes = ["security"]
severity_min = "info"
delivery = "sometimes"
scope = "local-only"`,
		`[[rule]]
recipient = "` + testNpub + `"
classes = ["security"]
severity_min = "info"
delivery = "immediate"
scope = "everywhere"`,
		`[[rule]]
recipient = "` + testNpub + `"
classes = []
severity_min = "info"
delivery = "immediate"
scope = "local-only"`,
	}
	for i, c := range cases {
		rules := writeTemp(t, dir, "policy.toml", c)
		if _, err := LoadPolicy(recipients, rules); err == nil {
			t.Errorf("case %d: expected validation error, got none", i)
		}
	}
}

func TestPolicyMatch(t *testing.T) {
	dir := t.TempDir()
	recipients := writeTemp(t, dir, "recipients.toml", `
[[recipient]]
npub = "`+testNpub+`"
role = "owner"
`)
	rules := writeTemp(t, dir, "policy.toml", `
[[rule]]
recipient = "`+testNpub+`"
classes = ["security", "recovery"]
severity_min = "warning"
delivery = "immediate"
scope = "local-only"
`)
	p, err := LoadPolicy(recipients, rules)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	if got := p.Match("security", "warning"); len(got) != 1 {
		t.Errorf("security/warning should match 1 rule, got %d", len(got))
	}
	if got := p.Match("security", "critical"); len(got) != 1 {
		t.Errorf("security/critical (above threshold) should still match, got %d", len(got))
	}
	if got := p.Match("security", "info"); len(got) != 0 {
		t.Errorf("security/info (below threshold) should not match, got %d", len(got))
	}
	if got := p.Match("backup", "critical"); len(got) != 0 {
		t.Errorf("backup class is not in the rule, should not match, got %d", len(got))
	}
}
