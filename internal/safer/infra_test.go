package safer

import "testing"

func TestTerraformDestroyIsDestructive(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "terraform",
		Args: []string{"destroy"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "destroy requires user attention")
}

func TestTerraformApplyAlertsInCarefulMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "terraform",
		Args: []string{"apply"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "apply changes infrastructure state")
}

func TestTerraformInitAlertsInCarefulMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "terraform",
		Args: []string{"init"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "init writes")
}
