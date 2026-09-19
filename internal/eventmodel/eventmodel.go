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
	"strconv"
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
	// KindDelegation: a server-scoped, expiring capability delegation.
	KindDelegation int = 27236
	// KindDelegationRevocation: revokes a delegation by event id.
	KindDelegationRevocation int = 27237

	// KindSystemEvent / KindServiceEvent / KindBackupEvent / KindSecurityEvent:
	// machine-state notices (system level, service state, backup outcome,
	// security events). Content: JSON object.
	KindSystemEvent   int = 2210
	KindServiceEvent  int = 2211
	KindBackupEvent   int = 2212
	KindSecurityEvent int = 2213
)

// Notice severities. System/service/backup/security events (2210-2213) that
// carry a "severity" field in their JSON content must use one of these — the
// notification service (roadmap §18.1) uses severity to apply per-recipient
// thresholds.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
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
	case kind == KindDelegation || kind == KindDelegationRevocation:
		// These are regular signed audit events despite using the 27236/27237
		// range next to NIP-98. They must survive relay replay/reconnect.
		return ClassImmutable
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
		KindDelegation, KindDelegationRevocation,
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
		return validateTrustPolicy(event)
	case KindBuildAttestation:
		return validateAddressable(event, "build attestation")
	case KindOperationRequest:
		return validateOperationRequest(event)
	case KindOperationApproval, KindOperationRejection, KindExecutionStarted, KindExecutionResult:
		return validateChainStep(event)
	case KindDelegation:
		return validateDelegation(event)
	case KindDelegationRevocation:
		return validateDelegationRevocation(event)
	case KindSystemEvent, KindServiceEvent, KindBackupEvent, KindSecurityEvent:
		return validateNotice(event)
	}
	return nil
}

// noticeBody is the optional convention carried by system/service/backup/
// security notices: a free-form "class" (e.g. "certificate", "update",
// "recovery", "cron", "health"), a "severity" (see the Severity* constants)
// and a human-readable "summary". All three are optional — a notice with no
// body at all is still valid JSON (or empty content) — but if "severity" is
// present it must be one of the known levels, since the notification service
// filters on it.
type noticeBody struct {
	Class    string `json:"class"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

func validateNotice(event *nostr.Event) error {
	if err := validateJSONContent(event, "notice payload"); err != nil {
		return err
	}
	if event.Content == "" {
		return nil
	}
	var body noticeBody
	if err := json.Unmarshal([]byte(event.Content), &body); err != nil {
		// Not an object shaped like noticeBody (e.g. a JSON array/scalar) —
		// still valid JSON, so leave it be; the convention is optional.
		return nil
	}
	switch body.Severity {
	case "", SeverityInfo, SeverityWarning, SeverityCritical:
	default:
		return kindError(event.Kind, "notice severity must be one of info|warning|critical")
	}
	return nil
}

func validateDelegation(event *nostr.Event) error {
	p := event.Tags.Find("p")
	server := event.Tags.Find("server")
	expiry := event.Tags.Find("expiry")
	if p == nil || len(p) < 2 || server == nil || len(server) < 2 || expiry == nil || len(expiry) < 2 {
		return kindError(event.Kind, "delegation requires p, server, and expiry tags")
	}
	if !validHex64(p[1]) || !validHex64(server[1]) {
		return kindError(event.Kind, "delegation p and server tags must be 64-hex pubkeys")
	}
	expiresAt, err := strconv.ParseInt(expiry[1], 10, 64)
	if err != nil || expiresAt <= 0 {
		return kindError(event.Kind, "delegation expiry must be a positive unix timestamp")
	}
	if event.Tags.Find("scope") == nil {
		return kindError(event.Kind, "delegation requires at least one scope tag")
	}
	return nil
}

func validateDelegationRevocation(event *nostr.Event) error {
	e := event.Tags.Find("e")
	if e == nil || len(e) < 2 || !validHex64(e[1]) {
		return kindError(event.Kind, "delegation revocation requires a 64-hex e tag")
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

// envelope is the shared optional addressable-document header
// (authority/event-protocol/envelope.md §1). Legacy documents omit it.
type envelope struct {
	Schema    *int   `json:"schema"`
	Revision  *int   `json:"revision"`
	Subject   string `json:"subject"`
	UpdatedBy string `json:"updated_by"`
	Reason    string `json:"reason"`
}

// validateEnvelope checks the shared envelope fields and, for addressable
// kinds, that a declared subject mirrors the d tag.
func validateEnvelope(event *nostr.Event, body []byte, addressable bool) error {
	if len(body) == 0 {
		return nil
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil // not an object; the kind validator reports content errors
	}
	if env.Schema != nil && *env.Schema < 1 {
		return kindError(event.Kind, "envelope 'schema' must be an integer >= 1")
	}
	if env.Revision != nil && *env.Revision < 0 {
		return kindError(event.Kind, "envelope 'revision' must be an integer >= 0")
	}
	if addressable && env.Subject != "" {
		d := event.Tags.Find("d")
		if d == nil || len(d) < 2 || env.Subject != d[1] {
			return kindError(event.Kind, "envelope 'subject' must mirror the 'd' tag")
		}
	}
	return nil
}

// validateTrustPolicy enforces the schema-versioned policy document contract:
// unlike legacy kinds, a trust/policy declaration must carry an envelope
// `schema` (authority/event-protocol/envelope.md §5).
func validateTrustPolicy(event *nostr.Event) error {
	if err := validateAddressable(event, "trust policy"); err != nil {
		return err
	}
	if err := validateEnvelope(event, []byte(event.Content), true); err != nil {
		return err
	}
	if event.Content == "" {
		return kindError(event.Kind, "trust policy must carry an envelope 'schema'")
	}
	var env envelope
	if err := json.Unmarshal([]byte(event.Content), &env); err != nil {
		return kindError(event.Kind, "trust policy content must be JSON: "+err.Error())
	}
	if env.Schema == nil {
		return kindError(event.Kind, "trust policy must carry an envelope 'schema'")
	}
	return nil
}

func validateCapability(event *nostr.Event) error {
	d := event.Tags.Find("d")
	if d == nil || len(d) < 2 {
		return kindError(event.Kind, "capability event requires a non-empty 'd' tag")
	}
	if !validHex64(d[1]) {
		return kindError(event.Kind, "capability event 'd' tag must be the subject pubkey (64-hex)")
	}
	if !json.Valid([]byte(event.Content)) {
		return kindError(event.Kind, "capability content must be JSON")
	}
	if err := validateEnvelope(event, []byte(event.Content), true); err != nil {
		return err
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(event.Content), &body); err != nil {
		return kindError(event.Kind, "capability content must be JSON")
	}
	var typeStr string
	if raw, ok := body["type"]; ok {
		if err := json.Unmarshal(raw, &typeStr); err != nil {
			return kindError(event.Kind, "capability content must declare a 'type'")
		}
	}
	if typeStr == "" {
		return kindError(event.Kind, "capability content must declare a 'type'")
	}
	if raw, ok := body["scopes"]; ok {
		var scopes []string
		if err := json.Unmarshal(raw, &scopes); err != nil {
			return kindError(event.Kind, "capability 'scopes' must be an array of strings")
		}
	}
	return nil
}

func validateIdentityDefinition(event *nostr.Event) error {
	d := event.Tags.Find("d")
	if d == nil || len(d) < 2 {
		return kindError(event.Kind, "identity definition requires a non-empty 'd' tag")
	}
	if !validHex64(d[1]) {
		return kindError(event.Kind, "identity definition 'd' tag must be the subject pubkey (64-hex)")
	}
	if !json.Valid([]byte(event.Content)) {
		return kindError(event.Kind, "identity definition content must be JSON")
	}
	if err := validateEnvelope(event, []byte(event.Content), true); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(event.Content), &raw); err != nil {
		return kindError(event.Kind, "identity definition content must be JSON")
	}
	var username, signerType string
	if value, ok := raw["username"]; ok {
		_ = json.Unmarshal(value, &username)
	}
	if value, ok := raw["signer_type"]; ok {
		if err := json.Unmarshal(value, &signerType); err != nil {
			return kindError(event.Kind, "identity definition signer_type must be one of nip07|nip46|passkey|unknown")
		}
	}
	enabled := true
	if value, ok := raw["enabled"]; ok {
		if err := json.Unmarshal(value, &enabled); err != nil {
			return kindError(event.Kind, "identity definition 'enabled' must be a boolean")
		}
	}
	if value, ok := raw["admin"]; ok {
		var admin bool
		if err := json.Unmarshal(value, &admin); err != nil {
			return kindError(event.Kind, "identity definition 'admin' must be a boolean")
		}
	}
	if strings.TrimSpace(username) == "" && enabled {
		return kindError(event.Kind, "identity definition content must declare a non-empty 'username'")
	}
	switch signerType {
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

// Notice extracts the class/severity/summary convention (see noticeBody)
// from a system/service/backup/security event. ok is false when the content
// is empty or not shaped like a notice body (callers should fall back to
// kind-derived defaults in that case).
func Notice(event *nostr.Event) (class, severity, summary string, ok bool) {
	if event.Content == "" {
		return "", "", "", false
	}
	var body noticeBody
	if err := json.Unmarshal([]byte(event.Content), &body); err != nil {
		return "", "", "", false
	}
	return body.Class, body.Severity, body.Summary, true
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
