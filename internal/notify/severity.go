package notify

import "github.com/imattau/nostrhost-control/internal/eventmodel"

// severityRank orders severities so a threshold comparison (severity_min) is
// a plain integer comparison. Unknown/empty values rank as info, the lowest
// level — a rule can't accidentally over-match by mis-typing a severity.
func severityRank(severity string) int {
	switch severity {
	case eventmodel.SeverityCritical:
		return 2
	case eventmodel.SeverityWarning:
		return 1
	default:
		return 0
	}
}

func validSeverity(s string) bool {
	switch s {
	case eventmodel.SeverityInfo, eventmodel.SeverityWarning, eventmodel.SeverityCritical:
		return true
	}
	return false
}
