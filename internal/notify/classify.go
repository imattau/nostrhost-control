package notify

import (
	"encoding/json"
	"fmt"

	"github.com/imattau/nostrhost-control/internal/eventmodel"
	"github.com/nbd-wtf/go-nostr"
)

// Item is a control-plane event reduced to what the notification service
// needs: a class to match against policy, a severity to threshold on, and a
// human-readable summary for the outbound DM. The originating event id is
// kept so the DM can reference the structured record it was derived from.
type Item struct {
	Class    string
	Severity string
	Summary  string
	EventID  string
	Kind     int
}

// Classify reduces a subscribed control-plane event to a notification Item.
// ok is false for kinds the notification service doesn't act on (the caller
// should simply skip those).
func Classify(event *nostr.Event) (Item, bool) {
	switch event.Kind {
	case eventmodel.KindOperationRequest:
		return classifyOperationRequest(event), true
	case eventmodel.KindExecutionResult:
		return classifyExecutionResult(event), true
	case eventmodel.KindBackupEvent:
		return classifyNotice(event, "backup", eventmodel.SeverityInfo), true
	case eventmodel.KindSecurityEvent:
		return classifyNotice(event, "security", eventmodel.SeverityWarning), true
	case eventmodel.KindSystemEvent:
		return classifyNotice(event, "system", eventmodel.SeverityInfo), true
	case eventmodel.KindServiceEvent:
		return classifyNotice(event, "service", eventmodel.SeverityInfo), true
	default:
		return Item{}, false
	}
}

// classifyNotice handles the four system/service/backup/security kinds,
// which all share the optional class/severity/summary content convention
// documented in EVENT-PROTOCOL.md §2.3. defaultClass/defaultSeverity apply
// when the event doesn't set them explicitly.
func classifyNotice(event *nostr.Event, defaultClass, defaultSeverity string) Item {
	class, severity, summary, ok := eventmodel.Notice(event)
	if !ok || class == "" {
		class = defaultClass
	}
	if !ok || severity == "" {
		severity = defaultSeverity
	}
	if !ok || summary == "" {
		summary = fmt.Sprintf("%s event", defaultClass)
	}
	return Item{Class: class, Severity: severity, Summary: summary, EventID: event.ID, Kind: event.Kind}
}

// classifyOperationRequest turns a pending kind-2200 request into an
// "approval" notice: the notification service does not itself track
// whether the request was later approved/rejected/executed (that stays the
// operation chain's job) — it simply surfaces that a request is waiting.
func classifyOperationRequest(event *nostr.Event) Item {
	var body struct {
		Tool string `json:"tool"`
	}
	_ = json.Unmarshal([]byte(event.Content), &body)
	summary := "approval required"
	if body.Tool != "" {
		summary = fmt.Sprintf("approval required: %s", body.Tool)
	}
	return Item{Class: "approval", Severity: eventmodel.SeverityWarning, Summary: summary, EventID: event.ID, Kind: event.Kind}
}

// classifyExecutionResult surfaces the outcome of an approved operation.
// Severity follows the "ok" field: failures are worth a higher default
// threshold than routine successes.
func classifyExecutionResult(event *nostr.Event) Item {
	var body struct {
		OK *bool `json:"ok"`
	}
	_ = json.Unmarshal([]byte(event.Content), &body)
	severity := eventmodel.SeverityInfo
	summary := "operation result"
	if body.OK != nil {
		if *body.OK {
			summary = "operation succeeded"
		} else {
			severity = eventmodel.SeverityWarning
			summary = "operation failed"
		}
	}
	return Item{Class: "operation", Severity: severity, Summary: summary, EventID: event.ID, Kind: event.Kind}
}
