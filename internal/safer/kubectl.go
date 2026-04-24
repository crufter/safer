package safer

func inspectKubectl(args []string, source string) []Finding {
	verb, rest := firstOperand(args)
	switch verb {
	case "":
		return nil
	case "delete":
		return []Finding{newFinding(source, RiskDataDelete, "kubectl delete requires user attention", "kubectl delete")}
	case "drain":
		return []Finding{newFinding(source, RiskDataDelete, "kubectl drain evicts workloads and requires user attention", "kubectl drain")}
	case "apply", "create", "replace", "edit", "patch", "scale", "autoscale", "annotate", "label", "set", "expose", "run", "cp", "taint", "cordon", "uncordon":
		return []Finding{newFinding(source, RiskEnvPersistent, "kubectl command changes cluster state", "kubectl "+verb)}
	case "rollout":
		sub, _ := firstOperand(rest)
		switch sub {
		case "restart", "undo", "pause", "resume":
			return []Finding{newFinding(source, RiskEnvEphemeral, "kubectl rollout changes workload state", "kubectl rollout "+sub)}
		case "", "history", "status":
			return nil
		default:
			return []Finding{newFinding(source, RiskUnknown, "kubectl rollout subcommand is not known read-only", "kubectl rollout "+sub)}
		}
	case "config":
		sub, _ := firstOperand(rest)
		switch sub {
		case "view", "current-context", "get-contexts":
			return nil
		default:
			return []Finding{newFinding(source, RiskDataWrite, "kubectl config command changes local kube config", "kubectl config "+sub)}
		}
	case "exec", "debug", "port-forward", "proxy":
		return []Finding{newFinding(source, RiskEnvEphemeral, "kubectl command opens an interactive or network path into the cluster", "kubectl "+verb)}
	case "auth":
		sub, _ := firstOperand(rest)
		if sub == "reconcile" {
			return []Finding{newFinding(source, RiskEnvPersistent, "kubectl auth reconcile changes RBAC state", "kubectl auth reconcile")}
		}
		return nil
	case "certificate":
		sub, _ := firstOperand(rest)
		if sub == "approve" || sub == "deny" {
			return []Finding{newFinding(source, RiskEnvPersistent, "kubectl certificate command changes cluster state", "kubectl certificate "+sub)}
		}
		return nil
	case "get", "describe", "logs", "top", "explain", "version", "api-resources", "api-versions", "cluster-info", "completion", "options", "diff", "wait":
		return nil
	default:
		return []Finding{newFinding(source, RiskUnknown, "kubectl subcommand is not known read-only", "kubectl "+verb)}
	}
}
