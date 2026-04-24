package safer

import "testing"

func TestSystemctlRestartAlertsInCarefulMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "systemctl",
		Args: []string{"restart", "api.service"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "changes service state")
}

func TestAWSDeleteOperationIsDestructive(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "aws",
		Args: []string{"s3api", "delete-bucket", "--bucket", "prod"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "destructive cloud operation")
}
