package safer

import "testing"

func TestDockerComposeDownIsDestructive(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "docker",
		Args: []string{"compose", "down"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "docker compose removes")
}

func TestDockerRestartAllowedInNondestructiveMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "docker",
		Args: []string{"restart", "api"},
		Mode: ModeNondestructive,
	})
	requireNoFindings(t, findings)
}

func TestDockerRestartAlertsInCarefulMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "docker",
		Args: []string{"restart", "api"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "docker command changes")
}
