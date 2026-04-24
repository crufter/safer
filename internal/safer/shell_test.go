package safer

import "testing"

func TestShellBlocksRmInBashCommand(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "bash",
		Args: []string{"-c", "rm -rf tmp"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "file deletion")
}

func TestShellBlocksRmInBashLoginCommand(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "bash",
		Args: []string{"-lc", "rm -rf tmp"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "file deletion")
}

func TestShellInspectsNestedSQLInBashLoginCommand(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "bash",
		Args: []string{"-lc", "psql -c 'DELETE FROM users WHERE id = 1'"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "DELETE requires user attention")
}

func TestShellCarefulBlocksNestedKubectlRestart(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "bash",
		Args: []string{"-lc", "kubectl -n prod rollout restart deployment/api"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "kubectl rollout changes workload state")
}

func TestShellDoesNotFlagRmAsEchoArgument(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "bash",
		Args: []string{"-c", "echo rm"},
		Mode: ModeNondestructive,
	})
	requireNoFindings(t, findings)
}

func TestShellCarefulBlocksRedirection(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "bash",
		Args: []string{"-lc", "echo hi > out.txt"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "shell redirection writes to a file")
}

func TestShellNondestructiveAllowsRedirection(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "bash",
		Args: []string{"-lc", "echo hi > out.txt"},
		Mode: ModeNondestructive,
	})
	requireNoFindings(t, findings)
}

func TestDirectToolBlocksRm(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "rm",
		Args: []string{"-rf", "tmp"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "file deletion")
}

func TestUnknownRequiresAllowUnknown(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "custom-tool",
		Args: []string{"status"},
	})
	requireFinding(t, findings, "not known read-only")
	requireRisk(t, findings, RiskUnknown)

	findings = CheckCommand(CheckRequest{
		Tool:         "custom-tool",
		Args:         []string{"status"},
		Capabilities: Capabilities{AllowUnknown: true},
	})
	requireNoFindings(t, findings)
}
