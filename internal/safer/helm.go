package safer

func inspectHelm(args []string, source string) []Finding {
	verb, rest := firstOperand(args)
	switch verb {
	case "":
		return nil
	case "uninstall", "delete":
		return []Finding{newFinding(source, RiskDataDelete, "helm uninstall/delete requires user attention", "helm "+verb)}
	case "install", "upgrade", "rollback", "create":
		return []Finding{newFinding(source, RiskEnvPersistent, "helm command changes release state", "helm "+verb)}
	case "package", "push", "pull":
		return []Finding{newFinding(source, RiskDataWrite, "helm command changes local chart state", "helm "+verb)}
	case "repo":
		sub, _ := firstOperand(rest)
		switch sub {
		case "add", "remove", "update", "index":
			return []Finding{newFinding(source, RiskDataWrite, "helm repo command changes local repository state", "helm repo "+sub)}
		case "list":
			return nil
		default:
			return []Finding{newFinding(source, RiskUnknown, "helm repo subcommand is not known read-only", "helm repo "+sub)}
		}
	case "dependency":
		sub, _ := firstOperand(rest)
		switch sub {
		case "build", "update":
			return []Finding{newFinding(source, RiskDataWrite, "helm dependency command writes chart dependencies", "helm dependency "+sub)}
		case "list":
			return nil
		default:
			return []Finding{newFinding(source, RiskUnknown, "helm dependency subcommand is not known read-only", "helm dependency "+sub)}
		}
	case "list", "ls", "status", "get", "history", "show", "search", "version", "env", "lint", "template":
		return nil
	default:
		return []Finding{newFinding(source, RiskUnknown, "helm subcommand is not known read-only", "helm "+verb)}
	}
}
