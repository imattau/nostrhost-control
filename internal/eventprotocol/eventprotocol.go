// Package eventprotocol is the Go reference consumer of the shared
// authority/event-protocol conformance corpus (WP1 of
// docs/RELAY-STATE-MIGRATION-PLAN.md).
//
// It validates the NostrHost custom kinds by delegating to the control-plane
// event model (internal/eventmodel), which is the implementation the relay
// actually enforces. The corpus is the source of truth; this package and the
// Python reference (tools/event_protocol.py) must reach the same verdicts.
package eventprotocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/imattau/nostrhost-control/internal/eventmodel"
	"github.com/nbd-wtf/go-nostr"
)

// Verdict is a validation outcome plus a stable reason code.
type Verdict struct {
	Accept bool
	Code   string
}

// Event is the corpus representation of a signed event. Only the fields the
// schema rules read are modelled.
type Event struct {
	ID        string     `json:"id"`
	Kind      int        `json:"kind"`
	CreatedAt int64      `json:"created_at"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	PubKey    string     `json:"pubkey"`
}

// CorpusDir returns the conformance corpus bundled with this module. The
// canonical corpus lives in the NostrHost superproject at
// authority/event-protocol/fixtures; this package carries a byte-identical
// mirror under testdata/ so the module is self-testing when built standalone.
// The superproject's CI runs `tools/event_protocol.py` and the drift check in
// tools/tests to keep the mirror honest.
func CorpusDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot resolve caller for corpus path")
	}
	return filepath.Join(filepath.Dir(file), "testdata"), nil
}

// Validate applies the event-protocol rules. NostrHost custom kinds are
// delegated to the control-plane event model; other kinds return accept (the
// relay treats standard NIP kinds as opaque).
func Validate(event Event) Verdict {
	nostrEvent := toNostr(event)
	if !eventmodel.IsCustomKind(event.Kind) {
		return Verdict{Accept: true}
	}
	if err := eventmodel.Validate(nostrEvent); err != nil {
		return Verdict{Accept: false, Code: reasonCode(err)}
	}
	return Verdict{Accept: true}
}

// reasonCode maps an eventmodel error to the corpus reason vocabulary
// (authority/event-protocol/envelope.md §2).
func reasonCode(err error) string {
	var modelErr *eventmodel.EventModelError
	if !errors.As(err, &modelErr) {
		return "schema-invalid"
	}
	return codeFor(modelErr.Kind, modelErr.Reason)
}

// codeFor translates the human-readable eventmodel reason into the stable
// corpus code. The mapping mirrors tools/event_protocol.py exactly.
func codeFor(kind int, reason string) string {
	trimmed := strings.TrimSpace(reason)
	switch {
	case strings.Contains(trimmed, "'subject' must mirror"):
		return "subject-mismatch"
	case strings.Contains(trimmed, "'schema' must be an integer"):
		return "schema-invalid"
	case strings.Contains(trimmed, "'revision' must be an integer"):
		return "revision-invalid"
	case strings.Contains(trimmed, "must carry an envelope 'schema'"):
		return "31101:missing-schema"
	case strings.Contains(trimmed, "content must be JSON"):
		return "content-not-json"
	}

	switch kind {
	case eventmodel.KindCapability:
		switch {
		case strings.Contains(trimmed, "must be the subject pubkey"):
			return "d-not-hex64"
		case strings.Contains(trimmed, "'d' tag"):
			return "missing-d"
		case strings.Contains(trimmed, "declare a 'type'"):
			return "31100:missing-type"
		case strings.Contains(trimmed, "'scopes' must be an array"):
			return "31100:scopes-not-array"
		}
	case eventmodel.KindTrustPolicy:
		if strings.Contains(trimmed, "'d' tag") {
			return "missing-d"
		}
	case eventmodel.KindIdentityDefinition:
		switch {
		case strings.Contains(trimmed, "must be the subject pubkey"):
			return "d-not-hex64"
		case strings.Contains(trimmed, "'d' tag"):
			return "missing-d"
		case strings.Contains(trimmed, "non-empty 'username'"):
			return "31102:missing-username"
		case strings.Contains(trimmed, "signer_type must be one of"):
			return "31102:bad-signer-type"
		case strings.Contains(trimmed, "'enabled' must be a boolean"):
			return "31102:enabled-not-bool"
		case strings.Contains(trimmed, "'admin' must be a boolean"):
			return "31102:admin-not-bool"
		}
	case eventmodel.KindDelegation:
		switch {
		case strings.Contains(trimmed, "p, server, and expiry"), strings.Contains(trimmed, "p and server tags"):
			return "27236:bad-tags"
		case strings.Contains(trimmed, "expiry must be"):
			return "27236:bad-expiry"
		case strings.Contains(trimmed, "at least one scope"):
			return "27236:missing-scope"
		}
	case eventmodel.KindDelegationRevocation:
		if strings.Contains(trimmed, "64-hex e tag") {
			return "27237:missing-e"
		}
	}
	return "schema-invalid"
}

func toNostr(event Event) *nostr.Event {
	tags := nostr.Tags{}
	for _, tag := range event.Tags {
		tags = append(tags, nostr.Tag(tag))
	}
	return &nostr.Event{
		ID:        event.ID,
		PubKey:    event.PubKey,
		CreatedAt: nostr.Timestamp(event.CreatedAt),
		Kind:      event.Kind,
		Tags:      tags,
		Content:   event.Content,
	}
}

// Fixture is one entry in verdicts.json.
type Fixture struct {
	ID         string   `json:"id"`
	Validators []string `json:"validators"`
	Event      Event    `json:"event"`
	Expect     struct {
		Accept bool   `json:"accept"`
		Code   string `json:"code"`
	} `json:"expect"`
}

// LoadVerdicts reads verdicts.json from the corpus.
func LoadVerdicts() ([]Fixture, error) {
	dir, err := CorpusDir()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "verdicts.json"))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Fixtures []Fixture `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc.Fixtures, nil
}
