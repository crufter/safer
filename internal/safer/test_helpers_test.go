package safer

import (
	"strings"
	"testing"
)

func requireFinding(t *testing.T, findings []Finding, want string) {
	t.Helper()
	for _, finding := range findings {
		if strings.Contains(finding.Reason, want) || strings.Contains(finding.Detail, want) {
			return
		}
	}
	t.Fatalf("expected finding containing %q, got %#v", want, findings)
}

func requireNoFindings(t *testing.T, findings []Finding) {
	t.Helper()
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func requireRisk(t *testing.T, findings []Finding, want Risk) {
	t.Helper()
	for _, finding := range findings {
		if finding.Risk == want {
			return
		}
	}
	t.Fatalf("expected risk %q, got %#v", want, findings)
}
