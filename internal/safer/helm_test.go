package safer

import "testing"

func TestHelmUninstallIsDestructive(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "helm",
		Args: []string{"uninstall", "api"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "helm uninstall")
}

func TestHelmUpgradeAlertsInCarefulMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "helm",
		Args: []string{"upgrade", "api", "./chart"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "helm command changes release")
}
