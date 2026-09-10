// Package notify is the NostrHost native notification service (roadmap
// §18.1): it subscribes to structured control-plane notices on the local
// relay and delivers human-readable summaries to configured npubs as
// encrypted Nostr direct messages (NIP-17/NIP-59), per the design in the
// umbrella repo's docs/NOTIFICATION-SERVICE.md.
//
// It never turns the administrative event protocol into a chat protocol:
// the structured event stays the system of record: a private message is a
// notification derived from it, not a replacement for it.
package notify

import (
	"fmt"
	"os"

	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/pelletier/go-toml/v2"
)

// Delivery is how a matched notice reaches its recipient.
type Delivery string

const (
	// DeliveryImmediate sends a DM as soon as a matching notice arrives.
	DeliveryImmediate Delivery = "immediate"
	// DeliverySummary batches matching notices into a periodic digest DM.
	DeliverySummary Delivery = "summary"
)

// Scope constrains which relays a notification may be delivered through.
type Scope string

const (
	// ScopeLocalOnly restricts delivery to the configured local/outbound
	// relay set.
	ScopeLocalOnly Scope = "local-only"
	// ScopeExternal permits delivery via relays the recipient's own NIP-65
	// list names.
	ScopeExternal Scope = "external"
)

// Recipient is a named notification target (state/notifications/recipients.toml).
type Recipient struct {
	Npub string `toml:"npub"`
	Role string `toml:"role"`

	pubkey string // decoded hex, set by Validate
}

// Pubkey returns the recipient's decoded hex public key.
func (r Recipient) Pubkey() string { return r.pubkey }

// Rule is one notification policy rule (state/notifications/policy.toml).
type Rule struct {
	Recipient    string   `toml:"recipient"` // npub, must match a Recipient
	Classes      []string `toml:"classes"`
	SeverityMin  string   `toml:"severity_min"`
	DeliveryMode Delivery `toml:"delivery"`
	Scope        Scope    `toml:"scope"`
}

// Policy is the loaded, validated notification configuration.
type Policy struct {
	Recipients []Recipient
	Rules      []Rule

	byNpub map[string]Recipient
}

type recipientsFile struct {
	Recipients []Recipient `toml:"recipient"`
}

type policyFile struct {
	Rules []Rule `toml:"rule"`
}

// LoadPolicy reads recipients.toml and policy.toml and returns a validated
// Policy. Both paths follow the state/notifications/ layout from
// docs/STATELAYER.md §18.6 in the umbrella repo, but LoadPolicy itself is
// agnostic to where the files live.
func LoadPolicy(recipientsPath, policyPath string) (Policy, error) {
	rf, err := readRecipients(recipientsPath)
	if err != nil {
		return Policy{}, err
	}
	pf, err := readPolicyRules(policyPath)
	if err != nil {
		return Policy{}, err
	}
	p := Policy{Recipients: rf.Recipients, Rules: pf.Rules}
	if err := p.validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func readRecipients(path string) (recipientsFile, error) {
	var rf recipientsFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return rf, fmt.Errorf("notify: read recipients %s: %w", path, err)
	}
	if err := toml.Unmarshal(raw, &rf); err != nil {
		return rf, fmt.Errorf("notify: parse recipients %s: %w", path, err)
	}
	return rf, nil
}

func readPolicyRules(path string) (policyFile, error) {
	var pf policyFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return pf, fmt.Errorf("notify: read policy %s: %w", path, err)
	}
	if err := toml.Unmarshal(raw, &pf); err != nil {
		return pf, fmt.Errorf("notify: parse policy %s: %w", path, err)
	}
	return pf, nil
}

func (p *Policy) validate() error {
	p.byNpub = make(map[string]Recipient, len(p.Recipients))
	for i, r := range p.Recipients {
		if r.Npub == "" {
			return fmt.Errorf("notify: recipient %d: npub is required", i)
		}
		prefix, value, err := nip19.Decode(r.Npub)
		if err != nil || prefix != "npub" {
			return fmt.Errorf("notify: recipient %d: invalid npub %q", i, r.Npub)
		}
		pk, ok := value.(string)
		if !ok || pk == "" {
			return fmt.Errorf("notify: recipient %d: invalid npub %q", i, r.Npub)
		}
		r.pubkey = pk
		p.Recipients[i] = r
		if _, dup := p.byNpub[r.Npub]; dup {
			return fmt.Errorf("notify: duplicate recipient npub %q", r.Npub)
		}
		p.byNpub[r.Npub] = r
	}

	for i, r := range p.Rules {
		if _, ok := p.byNpub[r.Recipient]; !ok {
			return fmt.Errorf("notify: rule %d: recipient %q is not declared in recipients.toml", i, r.Recipient)
		}
		if len(r.Classes) == 0 {
			return fmt.Errorf("notify: rule %d: at least one class is required", i)
		}
		if !validSeverity(r.SeverityMin) {
			return fmt.Errorf("notify: rule %d: severity_min %q must be one of info|warning|critical", i, r.SeverityMin)
		}
		switch r.DeliveryMode {
		case DeliveryImmediate, DeliverySummary:
		default:
			return fmt.Errorf("notify: rule %d: delivery %q must be immediate|summary", i, r.DeliveryMode)
		}
		switch r.Scope {
		case ScopeLocalOnly, ScopeExternal:
		default:
			return fmt.Errorf("notify: rule %d: scope %q must be local-only|external", i, r.Scope)
		}
	}
	return nil
}

// RecipientPubkey returns the decoded hex pubkey for a recipient npub.
func (p Policy) RecipientPubkey(npub string) (string, bool) {
	r, ok := p.byNpub[npub]
	if !ok {
		return "", false
	}
	return r.pubkey, true
}

// Match returns every rule whose class set includes class and whose
// severity_min is at or below severity.
func (p Policy) Match(class, severity string) []Rule {
	var out []Rule
	for _, r := range p.Rules {
		if !containsClass(r.Classes, class) {
			continue
		}
		if severityRank(severity) < severityRank(r.SeverityMin) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func containsClass(classes []string, class string) bool {
	for _, c := range classes {
		if c == class {
			return true
		}
	}
	return false
}
