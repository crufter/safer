package safer

import "testing"

func TestGitResetHardIsDestructive(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "git",
		Args: []string{"reset", "--hard"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "git reset")
}

func TestGitForcePushIsDestructive(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "git",
		Args: []string{"push", "--force-with-lease"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "git force push")
}

func TestGitCommitAlertsInCarefulMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "git",
		Args: []string{"commit", "-m", "change"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "git command changes")
}

func TestGitCommitRequiresDataWrite(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "git",
		Args: []string{"commit", "-m", "change"},
	})
	requireFinding(t, findings, "git command changes")
	requireRisk(t, findings, RiskDataWrite)

	findings = CheckCommand(CheckRequest{
		Tool:         "git",
		Args:         []string{"commit", "-m", "change"},
		Capabilities: Capabilities{DataWrite: true},
	})
	requireNoFindings(t, findings)
}

func TestGitPushRequiresEnvPersistent(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "git",
		Args: []string{"push"},
	})
	requireFinding(t, findings, "git push changes remote repository state")
	requireRisk(t, findings, RiskEnvPersistent)

	findings = CheckCommand(CheckRequest{
		Tool:         "git",
		Args:         []string{"push"},
		Capabilities: Capabilities{EnvPersistent: true},
	})
	requireNoFindings(t, findings)
}

func TestGitHubPRMergeIsDestructive(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "gh",
		Args: []string{"pr", "merge", "123"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "gh pr command changes")
}
