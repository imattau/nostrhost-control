package notify

import (
	"testing"

	"github.com/imattau/nostrhost-control/internal/eventmodel"
	"github.com/nbd-wtf/go-nostr"
)

func ev(kind int, content string) *nostr.Event {
	return &nostr.Event{ID: "deadbeef", Kind: kind, Content: content}
}

func TestClassifyOperationRequest(t *testing.T) {
	item, ok := Classify(ev(eventmodel.KindOperationRequest, `{"tool":"app.upgrade"}`))
	if !ok {
		t.Fatal("expected ok=true for operation request")
	}
	if item.Class != "approval" || item.Severity != eventmodel.SeverityWarning {
		t.Fatalf("unexpected item: %+v", item)
	}
	if item.Summary != "approval required: app.upgrade" {
		t.Fatalf("unexpected summary: %q", item.Summary)
	}
}

func TestClassifyExecutionResult(t *testing.T) {
	ok1, ok := Classify(ev(eventmodel.KindExecutionResult, `{"ok":true}`))
	if !ok || ok1.Severity != eventmodel.SeverityInfo {
		t.Fatalf("success should be info severity: %+v", ok1)
	}
	fail, ok := Classify(ev(eventmodel.KindExecutionResult, `{"ok":false}`))
	if !ok || fail.Severity != eventmodel.SeverityWarning {
		t.Fatalf("failure should be warning severity: %+v", fail)
	}
}

func TestClassifyNoticeDefaultsAndOverrides(t *testing.T) {
	backup, ok := Classify(ev(eventmodel.KindBackupEvent, ""))
	if !ok || backup.Class != "backup" || backup.Severity != eventmodel.SeverityInfo {
		t.Fatalf("empty backup notice should default to backup/info: %+v", backup)
	}

	sec, ok := Classify(ev(eventmodel.KindSecurityEvent, ""))
	if !ok || sec.Class != "security" || sec.Severity != eventmodel.SeverityWarning {
		t.Fatalf("empty security notice should default to security/warning: %+v", sec)
	}

	cert, ok := Classify(ev(eventmodel.KindSystemEvent, `{"class":"certificate","severity":"critical","summary":"cert expired"}`))
	if !ok || cert.Class != "certificate" || cert.Severity != eventmodel.SeverityCritical || cert.Summary != "cert expired" {
		t.Fatalf("system event should honour explicit class/severity/summary: %+v", cert)
	}
}

func TestClassifyIgnoresUnrelatedKinds(t *testing.T) {
	if _, ok := Classify(ev(eventmodel.KindCapability, "{}")); ok {
		t.Fatal("capability events should not be classified as notices")
	}
}
