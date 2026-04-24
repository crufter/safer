package safer

func inspectTerraform(tool string, args []string, source string) []Finding {
	verb, rest := firstOperand(args)
	switch verb {
	case "":
		return nil
	case "destroy":
		return []Finding{newFinding(source, RiskDataDelete, tool+" destroy requires user attention", tool+" destroy")}
	case "apply":
		if hasArg(rest, "-destroy") || hasArg(rest, "--destroy") {
			return []Finding{newFinding(source, RiskDataDelete, tool+" apply -destroy requires user attention", tool+" apply -destroy")}
		}
		return []Finding{newFinding(source, RiskEnvPersistent, tool+" apply changes infrastructure state", tool+" apply")}
	case "state":
		sub, _ := firstOperand(rest)
		switch sub {
		case "rm", "remove", "mv", "push", "replace-provider":
			return []Finding{newFinding(source, RiskDataDelete, tool+" state mutation requires user attention", tool+" state "+sub)}
		case "list", "show", "pull":
			return nil
		default:
			return []Finding{newFinding(source, RiskUnknown, tool+" state subcommand is not known read-only", tool+" state "+sub)}
		}
	case "import", "taint", "untaint", "force-unlock":
		return []Finding{newFinding(source, RiskEnvPersistent, tool+" command changes infrastructure state", tool+" "+verb)}
	case "workspace":
		sub, _ := firstOperand(rest)
		if sub == "delete" {
			return []Finding{newFinding(source, RiskDataDelete, tool+" workspace delete requires user attention", tool+" workspace delete")}
		}
		if sub == "new" || sub == "select" {
			return []Finding{newFinding(source, RiskDataWrite, tool+" workspace command changes local state", tool+" workspace "+sub)}
		}
		return nil
	case "plan":
		if hasFlagPrefix(rest, "-out") || hasFlagPrefix(rest, "--out") {
			return []Finding{newFinding(source, RiskDataWrite, tool+" plan writes a plan file", tool+" plan -out")}
		}
		return nil
	case "init":
		return []Finding{newFinding(source, RiskDataWrite, tool+" init writes provider/module state", tool+" init")}
	case "fmt":
		if hasArg(rest, "-check") || hasArg(rest, "--check") {
			return nil
		}
		return []Finding{newFinding(source, RiskDataWrite, tool+" fmt rewrites configuration files", tool+" fmt")}
	case "validate", "providers", "version", "output", "show", "graph", "console":
		return nil
	default:
		return []Finding{newFinding(source, RiskUnknown, tool+" subcommand is not known read-only", tool+" "+verb)}
	}
}

func inspectPulumi(args []string, source string) []Finding {
	verb, rest := firstOperand(args)
	switch verb {
	case "":
		return nil
	case "destroy":
		return []Finding{newFinding(source, RiskDataDelete, "pulumi destroy requires user attention", "pulumi destroy")}
	case "up", "refresh", "import", "cancel":
		return []Finding{newFinding(source, RiskEnvPersistent, "pulumi command changes stack state", "pulumi "+verb)}
	case "state":
		sub, _ := firstOperand(rest)
		switch sub {
		case "delete":
			return []Finding{newFinding(source, RiskDataDelete, "pulumi state delete requires user attention", "pulumi state delete")}
		case "rename", "move", "unprotect", "repair":
			return []Finding{newFinding(source, RiskEnvPersistent, "pulumi state command changes stack state", "pulumi state "+sub)}
		case "list":
			return nil
		default:
			return []Finding{newFinding(source, RiskUnknown, "pulumi state subcommand is not known read-only", "pulumi state "+sub)}
		}
	case "stack":
		sub, _ := firstOperand(rest)
		switch sub {
		case "rm", "remove":
			return []Finding{newFinding(source, RiskDataDelete, "pulumi stack removal requires user attention", "pulumi stack "+sub)}
		case "init", "select", "rename", "change-secrets-provider":
			return []Finding{newFinding(source, RiskEnvPersistent, "pulumi stack command changes local or remote state", "pulumi stack "+sub)}
		case "ls", "list", "output":
			return nil
		default:
			return []Finding{newFinding(source, RiskUnknown, "pulumi stack subcommand is not known read-only", "pulumi stack "+sub)}
		}
	case "config":
		sub, _ := firstOperand(rest)
		switch sub {
		case "rm", "remove":
			return []Finding{newFinding(source, RiskDataDelete, "pulumi config removal requires user attention", "pulumi config "+sub)}
		case "set", "set-all", "cp", "copy":
			return []Finding{newFinding(source, RiskEnvPersistent, "pulumi config command changes stack config", "pulumi config "+sub)}
		case "get":
			return nil
		default:
			return []Finding{newFinding(source, RiskUnknown, "pulumi config subcommand is not known read-only", "pulumi config "+sub)}
		}
	case "preview", "about", "version", "whoami", "login", "logout":
		return nil
	default:
		return []Finding{newFinding(source, RiskUnknown, "pulumi subcommand is not known read-only", "pulumi "+verb)}
	}
}
