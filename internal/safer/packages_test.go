package safer

import "testing"

func TestNPMUninstallIsDestructive(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "npm",
		Args: []string{"uninstall", "left-pad"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "removal command")
}

func TestNPMInstallAlertsInCarefulMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "npm",
		Args: []string{"install"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "changes dependencies")
}

func TestUVPipInstallAlertsInCarefulMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "uv",
		Args: []string{"pip", "install", "requests"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "changes dependencies")
}
