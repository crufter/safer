package safer

import "testing"

func TestKubectlGetIsReadonly(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "kubectl",
		Args: []string{"-n", "prod", "get", "pods"},
		Mode: ModeReadonly,
	})
	requireNoFindings(t, findings)
}

func TestKubectlDeleteIsDestructive(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "kubectl",
		Args: []string{"delete", "pod", "api-0"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "kubectl delete")
}

func TestKubectlRestartAllowedInNondestructiveMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "kubectl",
		Args: []string{"rollout", "restart", "deployment/api"},
		Mode: ModeNondestructive,
	})
	requireNoFindings(t, findings)
}

func TestKubectlRestartAlertsInCarefulMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "kubectl",
		Args: []string{"rollout", "restart", "deployment/api"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "kubectl rollout changes workload state")
}

func TestKubectlRestartRequiresEnvEphemeral(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "kubectl",
		Args: []string{"rollout", "restart", "deployment/api"},
	})
	requireFinding(t, findings, "kubectl rollout changes workload state")
	requireRisk(t, findings, RiskEnvEphemeral)

	findings = CheckCommand(CheckRequest{
		Tool:         "kubectl",
		Args:         []string{"rollout", "restart", "deployment/api"},
		Capabilities: Capabilities{EnvEphemeral: true},
	})
	requireNoFindings(t, findings)
}

func TestKubectlApplyRequiresEnvPersistent(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "kubectl",
		Args: []string{"apply", "-f", "deployment.yaml"},
	})
	requireFinding(t, findings, "kubectl command changes cluster state")
	requireRisk(t, findings, RiskEnvPersistent)

	findings = CheckCommand(CheckRequest{
		Tool:         "kubectl",
		Args:         []string{"apply", "-f", "deployment.yaml"},
		Capabilities: Capabilities{EnvPersistent: true},
	})
	requireNoFindings(t, findings)
}

func TestKubectlAuthReconcileAlertsInCarefulMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "kubectl",
		Args: []string{"auth", "reconcile", "-f", "rbac.yaml"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "kubectl auth reconcile")
}

func TestKubectlUnknownSubcommandAlertsInReadonlyMode(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "kubectl",
		Args: []string{"neat"},
		Mode: ModeReadonly,
	})
	requireFinding(t, findings, "not known read-only")
}
