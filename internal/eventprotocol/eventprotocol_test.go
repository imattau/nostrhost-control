package eventprotocol_test

import (
	"testing"

	"github.com/imattau/nostrhost-control/internal/eventprotocol"
)

// TestConformanceVerdicts runs every corpus fixture assigned to the Go
// validator. The corpus is the source of truth; a failure means the relay's
// enforcement (eventmodel) disagrees with the checked-in protocol contract.
func TestConformanceVerdicts(t *testing.T) {
	fixtures, err := eventprotocol.LoadVerdicts()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("corpus is empty")
	}
	ran := 0
	for _, fixture := range fixtures {
		if !contains(fixture.Validators, "go") {
			continue
		}
		ran++
		got := eventprotocol.Validate(fixture.Event)
		if got.Accept != fixture.Expect.Accept {
			t.Errorf("%s: accept=%v want %v", fixture.ID, got.Accept, fixture.Expect.Accept)
			continue
		}
		if !fixture.Expect.Accept && got.Code != fixture.Expect.Code {
			t.Errorf("%s: code=%q want %q", fixture.ID, got.Code, fixture.Expect.Code)
		}
	}
	if ran == 0 {
		t.Fatal("no fixtures target the Go validator")
	}
}

// TestReasonCodeVocabulary asserts every rejection code the corpus uses is
// producible by the Go implementation for a go-validated kind.
func TestReasonCodeVocabulary(t *testing.T) {
	fixtures, err := eventprotocol.LoadVerdicts()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	for _, fixture := range fixtures {
		if !contains(fixture.Validators, "go") || fixture.Expect.Accept {
			continue
		}
		got := eventprotocol.Validate(fixture.Event)
		if got.Code == "" {
			t.Errorf("%s: rejection produced an empty code", fixture.ID)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
