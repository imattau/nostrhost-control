// Package eventmodel defines the NostrHost control-plane event kinds and
// their schema validation.
//
// The kinds here are the minimal custom surface that standard Nostr
// primitives do not already cover (see the component → NIP mapping in the
// umbrella's docs/NIP-MAPPING.md). Numbers are placeholders to be validated
// against the live NIP registry before a release; they deliberately avoid the
// existing catalogue kinds (30063, 30267, 32267, and the bespoke 30078/30079/
// 30080 the catalogue is migrating away from).
package eventmodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nbd-wtf/go-nostr"
)

// Regular kinds (NIP-16: 1000–9999) — the operation chain and system notices.
// Every chain step is a unique, immutable, stored event: the audit trail.
const (
	// KindOperationRequest: an agent/service asks for a YunoHost operation.
	// Content: {"tool": "...", "args": {...}}. Optional ["p", target] tag.
	KindOperationRequest int = 2200
	// KindOperationApproval: an authorised identity approves request id.
	// Carries ["e", <request event id>].
	KindOperationApproval int = 2201
	// KindOperationRejection: an authorised identity rejects request id.
	// Carries ["e", <request event id>].
	KindOperationRejection int = 2202
	// KindExecutionStarted: the executor begins work on request id.
	// Carries ["e", <request event id>].
	KindExecutionStarted int = 2203
	// KindExecutionResult: the executor reports the outcome for request id.
	// Content: {"ok": bool, ...}. Carries ["e", <request event id>].
	KindExecutionResult int = 2204

	// KindSystemEvent / KindServiceEvent / KindBackupEvent / KindSecurityEvent:
	// machine-state notices (system level, service state, backup outcome,
	// security events). Content: JSON object.
	KindSystemEvent   int = 2210
	KindServiceEvent  int = 2211
	KindBackupEvent   int = 2212
	KindSecurityEvent int = 2213
)

// Addressable kinds (NIP-33: 30000–39999, d-tag keyed, replaceable per
// subject) — server-authoritative definitions.
const (
	// KindCapability: a role/capability grant for a subject. d = subject
	// pubkey (hex). Content: {"type": "...", "scopes": [...]}.
	KindCapability int = 31100
	// KindTrustPolicy: a server-authoritative trust/policy declaration that
	// is not expressible as a NIP-51 list. d = subject.
	KindTrustPolicy int = 31101
	// KindIdentityDefinition: the server-authoritative pubkey ↔ YunoHost
	// account mapping. d = subject pubkey (hex). Content:
	// {"username": "...", "signer_type": "...", "label": "...",
	//  "enabled": true}. Authored by an administrator (Phase 3) or by the
	// subject with proven account control (Phase 4 portal self-link).
	KindIdentityDefinition int = 31102
	// KindBuildAttestation: CI/build attestation for a package revision.
	// d = "repo:commit". Replaces the bespoke catalogue kind 30080.
	KindBuildAttestation int = 31300
)

// Retention classes.
const (
	// ClassImmutable: stored forever (audit chain, system notices).
	ClassImmutable = "immutable"
	// ClassReplaceable: latest per d-tag wins (definitions).
	ClassReplaceable = "replaceable"
	// ClassPrunable: stored, aged out after a TTL (e.g. operation requests).
	ClassPrunable = "prunable"
	// ClassEphemeral: not stored.
	ClassEphemeral = "ephemeral"
)

// Class returns the retention class for a kind.
func Class(kind int) string {
	switch {
	case kind >= 20000 && kind <= 29999:
		return ClassEphemeral
	case kind >= 10000 && kind <= 19999, kind >= 30000 && kind <= 39999:
		return ClassReplaceable
	default:
		return ClassImmutable
	}
}

// IsCustomKind reports whether kind belongs to NostrHost's own control-plane
// event model (and therefore gets schema validation here).
func IsCustomKind(kind int) bool {
	switch kind {
	case KindOperationRequest, KindOperationApproval, KindOperationRejection,
		KindExecutionStarted, KindExecutionResult, KindSystemEvent,
		KindServiceEvent, KindBackupEvent, KindSecurityEvent,
		KindCapability, KindTrustPolicy, KindIdentityDefinition, KindBuildAttestation:
		return true
	}
	return false
}

// ChainKinds returns the operation chain kinds (request → approval → …).
func ChainKinds() []int {
	return []int{KindOperationRequest, KindOperationApproval, KindOperationRejection,
		KindExecutionStarted, KindExecutionResult}
}

// EventModelError describes a schema validation failure for a custom kind.
type EventModelError struct {
	Kind   int
	Reason string
}

func (e *EventModelError) Error() string {
	return fmt.Sprintf("invalid kind %d event: %s", e.Kind, e.Reason)
}

var errNotCustom = errors.New("not a custom kind")

// Validate checks a custom NostrHost event's schema. It returns nil for
// non-custom kinds (validation only applies to our own kinds).
func Validate(event *nostr.Event) error {
	kind := event.Kind
	if !IsCustomKind(kind) {
		return nil
	}
	switch kind {
	case KindCapability:
		return validateCapability(event)
	case KindIdentityDefinition:
		return validateIdentityDefinition(event)
	case KindTrustPolicy:
		return validateAddressable(event, "trust policy")
	case KindBuildAttestation:
		return validateAddressable(event, "build attestation")
	case KindOperationRequest:
		return validateOperationRequest(event)
	case KindOperationApproval, KindOperationRejection, KindExecutionStarted, KindExecutionResult:
		return validateChainStep(event)
	case KindSystemEvent, KindServiceEvent, KindBackupEvent, KindSecurityEvent:
		return validateJSONContent(event, "event payload")
	}
	return nil
}

func kindError(kind int, reason string) error { return &EventModelError{Kind: kind, Reason: reason} }

func validHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func validateAddressable(event *nostr.Event, what string) error {
	d := event.Tags.Find("d")
	if d == nil || len(d) < 2 || d[1] == "" {
		return kindError(event.Kind, fmt.Sprintf("%s must carry a non-empty 'd' tag", what))
	}
	return validateJSONContent(event, what)
}

func validateCapability(event *nostr.Event) error {
	d := event.Tags.Find("d")
	if d == nil || len(d) < 2 || !validHex64(d[1]) {
		return kindError(event.Kind, "capability event 'd' tag must be the subject pubkey (64-hex)")
	}
	if err := validateJSONContent(event, "capability"); err != nil {
		return err
	}
	var body struct {
		Type   string   `json:"type"`
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal([]byte(event.Content), &body); err != nil {
		return kindError(event.Kind, "capability content must be JSON: "+err.Error())
	}
	if body.Type == "" {
		return kindError(event.Kind, "capability content must declare a 'type'")
	}
	return nil
}

func validateIdentityDefinition(event *nostr.Event) error {
	d := event.Tags.Find("d")
	if d == nil || len(d) < 2 || !validHex64(d[1]) {
		return kindError(event.Kind, "identity definition 'd' tag must be the subject pubkey (64-hex)")
	}
	var body struct {
		Username   string `json:"username"`
		SignerType string `json:"signer_type"`
		Label      string `json:"label"`
		Enabled    *bool  `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(event.Content), &body); err != nil {
		return kindError(event.Kind, "identity definition content must be JSON: "+err.Error())
	}
	if strings.TrimSpace(body.Username) == "" && (body.Enabled == nil || *body.Enabled) {
		return kindError(event.Kind, "identity definition content must declare a non-empty 'username'")
	}
	switch body.SignerType {
	case "", "nip07", "nip46", "passkey", "unknown":
	default:
		return kindError(event.Kind, "identity definition signer_type must be one of nip07|nip46|passkey|unknown")
	}
	return nil
}

func validateOperationRequest(event *nostr.Event) error {
	var body struct {
		Tool string `json:"tool"`
	}
	if err := json.Unmarshal([]byte(event.Content), &body); err != nil {
		return kindError(event.Kind, "operation request content must be JSON: "+err.Error())
	}
	if strings.TrimSpace(body.Tool) == "" {
		return kindError(event.Kind, "operation request content must declare a non-empty 'tool'")
	}
	return nil
}

func validateChainStep(event *nostr.Event) error {
	e := event.Tags.Find("e")
	if e == nil || len(e) < 2 || e[1] == "" {
		return kindError(event.Kind, "operation chain events must reference the request via an 'e' tag")
	}
	return validateJSONContent(event, "chain step")
}

func validateJSONContent(event *nostr.Event, what string) error {
	if event.Content == "" {
		return nil // empty content is acceptable where optional
	}
	var v any
	if err := json.Unmarshal([]byte(event.Content), &v); err != nil {
		return kindError(event.Kind, fmt.Sprintf("%s content must be valid JSON", what))
	}
	return nil
}
